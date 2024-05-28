use std::collections::HashMap;

use ckb_sdk::{
    core::TransactionBuilder,
    transaction::{
        builder::{ChangeBuilder, CkbTransactionBuilder, DefaultChangeBuilder},
        handler::HandlerContexts,
        input::TransactionInput,
        TransactionBuilderConfiguration,
    },
    tx_builder::{BalanceTxCapacityError, TxBuilderError},
    NetworkInfo, NetworkType, ScriptGroup, TransactionWithScriptGroups,
};
use ckb_types::{
    core::{Capacity, ScriptHashType},
    h256,
    packed::{self, Byte32, CellDep, CellOutput, Script},
    prelude::{Builder, Entity, Pack},
};
use scroll::ctx::TryFromCtx;

pub mod handler;

/// A xUDT transaction builder implementation
pub struct XudtTransactionBuilder {
    pub sender_lock: Script,
    pub capacity_provider: Script,
    pub configuration: TransactionBuilderConfiguration,
    pub xudt_args: Vec<u8>,

    pub inputs: Vec<TransactionInput>,
    pub input_amount: u128,
    pub output_amount: u128,
    pub tx: TransactionBuilder,
}

impl XudtTransactionBuilder {
    pub fn new<S: Into<Script>>(
        sender_lock: S,
        capacity_provider: S,
        configuration: TransactionBuilderConfiguration,
        xudt_args: Vec<u8>,
    ) -> Self {
        XudtTransactionBuilder {
            sender_lock: sender_lock.into(),
            capacity_provider: capacity_provider.into(),
            configuration,
            xudt_args,
            inputs: Vec::new(),
            input_amount: 0,
            output_amount: 0,
            tx: Default::default(),
        }
    }

    pub fn add_cell_dep(&mut self, cell_dep: CellDep) {
        self.tx.cell_dep(cell_dep);
    }

    pub fn add_cell_deps(&mut self, cell_deps: Vec<CellDep>) {
        self.tx.cell_deps(cell_deps);
    }

    pub fn add_input(&mut self, input: TransactionInput, udt_amount: u128) {
        self.input_amount += udt_amount;
        self.inputs.push(input);
    }

    /// Add an output cell and output data to the transaction.
    pub fn add_output_and_data(&mut self, output: CellOutput, data: packed::Bytes) {
        self.tx.output(output);
        self.tx.output_data(data);
    }

    pub fn add_ckb_output<S: Into<Script>>(&mut self, output_lock_script: S, capacity: u64) {
        let dummy_output = CellOutput::new_builder()
            .lock(output_lock_script.into())
            .build();
        let output = dummy_output.as_builder().capacity(capacity.pack()).build();
        self.add_output_and_data(output, Default::default());
    }

    /// Add an output cell with the given lock script and xudt amount
    pub fn add_udt_output<S: Into<Script>>(&mut self, output_lock_script: S, xudt_amount: u128) {
        let type_script =
            build_xudt_type_script(self.configuration.network_info(), self.xudt_args.clone());
        let output_data = xudt_amount.to_le_bytes().pack();
        let dummy_output = CellOutput::new_builder()
            .lock(output_lock_script.into())
            .type_(Some(type_script).pack())
            .build();
        let required_capacity = dummy_output
            .occupied_capacity(Capacity::bytes(output_data.len()).unwrap())
            .unwrap()
            .pack();
        let output = dummy_output
            .as_builder()
            .capacity(required_capacity)
            .build();
        self.add_output_and_data(output, output_data);
        self.output_amount += xudt_amount;
    }
}

impl CkbTransactionBuilder for XudtTransactionBuilder {
    fn build(
        mut self,
        contexts: &HandlerContexts,
    ) -> Result<TransactionWithScriptGroups, TxBuilderError> {
        if self.input_amount < self.output_amount {
            return Err(TxBuilderError::BalanceCapacity(
                BalanceTxCapacityError::CapacityNotEnough("udt".to_string()),
            ));
        }

        let change_amount = self.input_amount - self.output_amount;
        if change_amount > 0 {
            let sender_lock = self.sender_lock.clone();
            self.add_udt_output(sender_lock, change_amount);
        }

        let mut lock_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
        let mut type_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();

        let Self {
            sender_lock: _,
            capacity_provider,
            configuration,
            xudt_args: _,
            inputs,
            input_amount: _,
            output_amount: _,
            mut tx,
        } = self;

        let mut change_builder =
            DefaultChangeBuilder::new(&configuration, capacity_provider, Vec::new());

        // setup outputs' type script group
        for (output_idx, output) in tx.get_outputs().clone().iter().enumerate() {
            if let Some(type_script) = &output.type_().to_opt() {
                type_groups
                    .entry(type_script.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_type_script(type_script))
                    .output_indices
                    .push(output_idx);
            }
        }

        // collect inputs
        let mut udt_amt_occupied = 0u128;
        for (input_index, input) in inputs.into_iter().enumerate() {
            tx.input(input.cell_input());
            tx.witness(packed::Bytes::default());

            let previous_output = input.previous_output();
            let lock_script = previous_output.lock();
            lock_groups
                .entry(lock_script.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_lock_script(&lock_script))
                .input_indices
                .push(input_index);

            if let Some(type_script) = previous_output.type_().to_opt() {
                type_groups
                    .entry(type_script.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_type_script(&type_script))
                    .input_indices
                    .push(input_index);
            }

            // check if we have enough udt
            if input.live_cell.output_data.as_ref().len().eq(&16) {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(input.live_cell.output_data.as_ref());
                if let Ok((amt, _)) = u128::try_from_ctx(&buf, scroll::Endian::Little) {
                    udt_amt_occupied += amt;
                    if udt_amt_occupied < self.output_amount {
                        continue;
                    }
                } else {
                    continue;
                }
            } else {
                continue;
            }


            // check if we have enough inputs
            if change_builder.check_balance(input, &mut tx) {
                // handle script groups
                let mut script_groups: Vec<ScriptGroup> = lock_groups
                    .into_values()
                    .chain(type_groups.into_values())
                    .collect();

                for script_group in script_groups.iter_mut() {
                    for handler in configuration.get_script_handlers() {
                        for context in &contexts.contexts {
                            if handler.build_transaction(&mut tx, script_group, context.as_ref())? {
                                break;
                            }
                        }
                    }
                }

                let tx_view = change_builder.finalize(tx);

                return Ok(TransactionWithScriptGroups::new(tx_view, script_groups));
            }
        }

        Err(
            BalanceTxCapacityError::CapacityNotEnough("can not find enough inputs".to_string())
                .into(),
        )
    }
}

pub fn build_xudt_type_script(network_info: &NetworkInfo, xudt_args: Vec<u8>) -> Script {
    // code_hash from https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0025-simple-udt/0025-simple-udt.md#notes
    let xudt_script = match network_info.network_type {
        NetworkType::Mainnet => Script::new_builder()
            .code_hash(
                h256!("0x50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95").pack(),
            )
            .hash_type(ScriptHashType::Data1.into())
            .args(xudt_args.pack())
            .build(),
        NetworkType::Testnet => Script::new_builder()
            .code_hash(
                h256!("0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb").pack(),
            )
            .hash_type(ScriptHashType::Type.into())
            .args(xudt_args.pack())
            .build(),
        _ => panic!("Unsupported network type"),
    };

    xudt_script
}
