use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types::{TransactionView, Uint32};
use ckb_sdk::transaction::input::TransactionInput;
use ckb_sdk::unlock::ScriptUnlocker;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    traits::{CellCollector, CellQueryOptions, DefaultCellCollector, ValueRangeOption},
    transaction::{
        builder::CkbTransactionBuilder,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    {Address, AddressPayload, CkbRpcClient, NetworkInfo, SECP256K1},
};
use ckb_types::core:: Capacity;
use ckb_types::packed::Uint64;
use ckb_types::prelude::Unpack;
use ckb_types::{
    bytes::Bytes,
    core::{DepType, ScriptHashType},
    h256,
    packed::{Bytes as PackBytes, CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::{Builder, Entity, Pack},
    H256,
};
use std::env;
use std::error::{Error as StdErr, Error};
use std::str::FromStr;
use xudt_manager::{handler::XudtHandler, XudtTransactionBuilder};

const UNIQUE_ARGS_SIZE: usize = 20;
const ISSUE_DECIMAL: u8 = 8;
const ISSUE_NAME: &'static str = "XUDT Test T Token";
const ISSUE_SYMBOL: &'static str = "XTTT";
const ISSUE_AMOUNT: u128 = 2100_000;

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let mut configuration =
        TransactionBuilderConfiguration::new_with_network(network_info.clone())?;
    configuration
        .register_script_handler(Box::new(XudtHandler::new_with_network(&network_info)?) as Box<_>);

    let issue_private_key_words = env::var("ISSUE_PRIVATE_KEY")?;
    let issue_private_key = H256::from_str(issue_private_key_words.as_ref())?;

    let (issue_lock_script, issue_addr) = {
        let secret_key = secp256k1::SecretKey::from_slice(issue_private_key.clone().as_bytes())
            .map_err(|err| format!("invalid sender secret key: {}", err))?;

        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &secret_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        let payload = AddressPayload::from_pubkey(&pubkey);
        (
            Script::new_builder()
                .code_hash(SIGHASH_TYPE_HASH.pack())
                .hash_type(ScriptHashType::Type.into())
                .args(Bytes::from(hash160).pack())
                .build(),
            Address::new(network_info.network_type, payload, true),
        )
    };

    println!("sender_addr: {}", issue_addr);

    let mut cell_collector = DefaultCellCollector::new(&network_info.url);

    let mut issue_xudt_builder = XudtTransactionBuilder::new(
        issue_lock_script.clone(),
        issue_lock_script.clone(),
        configuration,
        vec![],
    );

    let self_defiened_lockscript = Script::new_builder()
        .code_hash(
            h256!("0x733e5936c2e64772ff99b5f95d19a6ace0d99401c275a3619b1887eb11f81795").pack(),
        )
        .hash_type(ScriptHashType::Type.into())
        .args(encode_token_info().pack())
        .build();

    let xudt_type = Script::new_builder()
        .code_hash(
            h256!("0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb").pack(),
        )
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(self_defiened_lockscript.calc_script_hash().as_bytes()).pack())
        .build();

    let xudt_out_cell = CellOutput::new_builder()
        .lock(issue_lock_script.clone())
        .type_(Some(xudt_type).pack())
        .build_exact_capacity(Capacity::bytes(16).unwrap())?;

    let unique_type_script_without_args = Script::new_builder()
        .code_hash(
            h256!("0x8e341bcfec6393dcd41e635733ff2dca00a6af546949f70c57a706c0f344df8b").pack(),
        )
        .hash_type(ScriptHashType::Type.into())
        .build();

    let dump_unique_out_cell = CellOutput::new_builder()
        .lock(issue_lock_script.clone())
        .type_(Some(unique_type_script_without_args.clone()).pack())
        .build_exact_capacity(Capacity::bytes(encode_token_info().len()).unwrap())?;

    let min_total_capacity = <Uint64 as Unpack<u64>>::unpack(&xudt_out_cell.capacity())
        + <Uint64 as Unpack<u64>>::unpack(&dump_unique_out_cell.capacity())
        + Capacity::bytes(20).unwrap().as_u64() // unique args len 20
        + 1000;

    // udt_info_lock(self defined)
    let udt_info_lockscript_dec = CellDep::new_builder()
        .out_point(
            OutPoint::new_builder()
                .tx_hash(
                    h256!("0x793e6bc1a1866a6c01a78823f1adf1710591f7fc1e24face0abf7bd31fe9d00f")
                        .pack(),
                )
                .index(0u32.pack())
                .build(),
        )
        .build();

    // let ckb_tx = build_self_defined_lock_script_ckb_tx(
    //     min_total_capacity,
    //     vec![issue_private_key.clone()],
    //     issue_lock_script.clone(),
    //     network_info.clone(),
    //     self_defiened_lockscript.clone(),
    //         udt_info_lockscript_dec.clone()
    // ).unwrap();

    let ckb_query = {
        let mut query = CellQueryOptions::new_lock(self_defiened_lockscript.clone());
        query.primary_script = self_defiened_lockscript;
        query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
        query.data_len_range = Some(ValueRangeOption::new_exact(0));
        query.min_total_capacity = min_total_capacity;
        query
    };

    let mut ckb_cells = cell_collector.collect_live_cells(&ckb_query, true)?.0;
    ckb_cells.retain(|cell| cell.output.type_().is_none());
    assert!(!ckb_cells.is_empty());

    let unique_out_cell = dump_unique_out_cell
        .as_builder()
        .type_(
            Some(
                unique_type_script_without_args
                    .as_builder()
                    .args(generate_unique_type_args(
                        CellInput::new_builder()
                            .previous_output(ckb_cells[0].clone().out_point)
                            .build(),
                        1,
                    ))
                    .build(),
            )
            .pack(),
        )
        .build();

    for cell in ckb_cells {
        issue_xudt_builder.add_input(
            TransactionInput {
                live_cell: cell,
                since: 0,
            },
            0,
        )
    }

    let issue_amount = ISSUE_AMOUNT * (10u128.pow(ISSUE_DECIMAL as u32));
    issue_xudt_builder.add_output_and_data(xudt_out_cell, issue_amount.to_le_bytes().pack());

    issue_xudt_builder.add_output_and_data(unique_out_cell, encode_token_info().pack());

    issue_xudt_builder.add_cell_deps(vec![
        CellDep::new_builder()
            .out_point(
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37")
                            .pack(),
                    )
                    .index(0u32.pack())
                    .build(),
            )
            .dep_type(DepType::DepGroup.into())
            .build(),
        CellDep::new_builder()
            .out_point(
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0xff91b063c78ed06f10a1ed436122bd7d671f9a72ef5f5fa28d05252c17cf4cef")
                            .pack(),
                    )
                    .index(0u32.pack())
                    .build(),
            )
            .build(),
        CellDep::new_builder()
            .out_point(
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0xbf6fb538763efec2a70a6a3dcb7242787087e1030c4e7d86585bc63a9d337f5f")
                            .pack(),
                    )
                    .index(0u32.pack())
                    .build(),
            )
            .build(),
        // udt_info_lock(self defined)
        udt_info_lockscript_dec,
    ]);

    let mut tx_with_groups = issue_xudt_builder.build(&Default::default())?;
    let private_keys = vec![issue_private_key.clone()];
    TransactionSigner::new(&network_info)
        .sign_transaction(
            &mut tx_with_groups,
            &SignContexts::new_sighash_h256(private_keys).unwrap(),
        )
        .unwrap();

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let tx_hash = CkbRpcClient::new(network_info.url.as_str())
        .send_transaction(json_tx.inner, None)
        .expect("send transaction");

    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}

fn build_self_defined_lock_script_ckb_tx(
    capacity: u64,
    sender_keys: Vec<H256>,
    sender_lock: Script,
    network_info: NetworkInfo,
    self_defined_lock_script: Script,
    self_defined_lock_script_dep: CellDep,
) -> Result<TransactionView, Box<dyn Error>> {
    let mut cell_collector = DefaultCellCollector::new(&network_info.url);
    let mut configuration =
        TransactionBuilderConfiguration::new_with_network(network_info.clone())?;
    configuration
        .register_script_handler(Box::new(XudtHandler::new_with_network(&network_info)?) as Box<_>);

    let mut builder = XudtTransactionBuilder::new(
        sender_lock.clone(),
        sender_lock.clone(),
        configuration,
        vec![],
    );

    let ckb_query = {
        let mut query = CellQueryOptions::new_lock(sender_lock.clone());
        query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
        query.data_len_range = Some(ValueRangeOption::new_exact(0));
        query.min_total_capacity = capacity;
        query
    };

    let mut ckb_cells = cell_collector.collect_live_cells(&ckb_query, true)?.0;
    ckb_cells.retain(|cell| cell.output.type_().is_none());
    assert!(!ckb_cells.is_empty());

    for cell in ckb_cells {
        builder.add_input(
            TransactionInput {
                live_cell: cell,
                since: 0,
            },
            0,
        )
    }

    let output = CellOutput::new_builder()
        .lock(self_defined_lock_script)
        .capacity(capacity.pack())
        .build();

    builder.add_output_and_data(output, Default::default());
    builder.add_cell_dep(self_defined_lock_script_dep);

    let mut tx_with_groups = builder.build(&Default::default())?;
    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!(
        "self_defined_lock_script_ckb_tx: {}",
        serde_json::to_string_pretty(&json_tx).unwrap()
    );

    TransactionSigner::new(&network_info).sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_sighash_h256(sender_keys)?,
    )?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!(
        "self_defined_lock_script_ckb_tx: {}",
        serde_json::to_string_pretty(&json_tx).unwrap()
    );

    let tx_hash = CkbRpcClient::new(network_info.url.as_str())
        .send_transaction(json_tx.clone().inner, None)
        .expect("send self_defined_lock_script_ckb_tx transaction");
    println!(">>> self_defined_lock_script_ckb_tx {} sent! <<<", tx_hash);

    Ok(json_tx)
}

fn generate_unique_type_args(first_input: CellInput, first_output_index: u64) -> PackBytes {
    let input = first_input.as_bytes();
    let mut hasher = new_blake2b();
    hasher.update(input.as_ref());
    hasher.update(first_output_index.to_le_bytes().as_ref());
    let mut args = [0u8; 40];
    hasher.finalize(&mut args);
    args[0..UNIQUE_ARGS_SIZE].pack()
}

fn encode_token_info() -> Vec<u8> {
    [
        &[ISSUE_DECIMAL],
        &[ISSUE_NAME.len() as u8],
        ISSUE_NAME.as_bytes(),
        &[ISSUE_SYMBOL.len() as u8],
        ISSUE_SYMBOL.as_bytes(),
    ]
    .concat()
}

#[test]
fn load_tx_info() {
    let network_info = NetworkInfo::testnet();
    let client = CkbRpcClient::new(network_info.url.as_str());
    let result = client
        .get_live_cell(
            OutPoint::new_builder()
                .index(Uint32::from(0).pack())
                .tx_hash(
                    h256!("0x3cf494e6da5858047a456825c40f9c784710dfc69006abbcffaffbabb6cd5097")
                        .pack(),
                )
                .build()
                .into(),
            true,
        )
        .unwrap();
    let cell = result.cell.unwrap();
    println!("output.type_ {:?}", cell.output.type_);
    println!("output.lock {:?}", cell.output.lock);
    println!("output.capacity {:?}", cell.output.capacity)
}
