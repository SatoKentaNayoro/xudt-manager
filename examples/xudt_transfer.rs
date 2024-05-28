use ckb_hash::blake2b_256;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::ckb_indexer::SearchMode,
    traits::{CellCollector, CellQueryOptions, DefaultCellCollector, ValueRangeOption},
    transaction::{
        builder::CkbTransactionBuilder,
        input::TransactionInput,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    Address, AddressPayload, CkbRpcClient, NetworkInfo, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::ScriptHashType,
    h256,
    packed::Script,
    prelude::{Builder, Entity, Pack},
};
use std::error::Error as StdErr;
use xudt_manager::{build_xudt_type_script, handler::XudtHandler, XudtTransactionBuilder};

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let mut configuration =
        TransactionBuilderConfiguration::new_with_network(network_info.clone())?;
    configuration
        .register_script_handler(Box::new(XudtHandler::new_with_network(&network_info)?) as Box<_>);

    let sender_private_key =
        h256!("0x0000000000000000000000000000000000000000000000000000000000000420");

    let (sender_lock_script, sender_addr) = {
        let secret_key = secp256k1::SecretKey::from_slice(sender_private_key.as_bytes())
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

    println!("sender_addr: {}", sender_addr);

    let receiver_private_key =
        h256!("0x0000000000000000000000000000000000000000000000000000000000000420");

    let (receiver_lock_script, receiver_addr) = {
        let secret_key = secp256k1::SecretKey::from_slice(receiver_private_key.as_bytes())
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

    println!("receiver_addr: {}", receiver_addr);

    let xudt_args: Vec<u8> = vec![];
    let xudt_script = build_xudt_type_script(&network_info, xudt_args.clone());

    let network_info = NetworkInfo::testnet();
    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let mut cell_collector = DefaultCellCollector::new(&network_info.url);

    let mut udt_query = CellQueryOptions::new_lock(sender_lock_script.clone());
    udt_query.script_search_mode = Some(SearchMode::Exact);
    udt_query.secondary_script = Some(xudt_script);
    udt_query.with_data = Some(true);

    let (udt_live_cell, capacity) = cell_collector.collect_live_cells(&udt_query, true).unwrap();

    let mut ckb_query = CellQueryOptions::new_lock(sender_lock_script.clone());
    ckb_query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
    ckb_query.data_len_range = Some(ValueRangeOption::new_exact(0));

    let (ckb_live_cell, capacity) = cell_collector.collect_live_cells(&udt_query, true).unwrap();

    let mut builder = XudtTransactionBuilder::new(
        sender_lock_script.clone(),
        sender_lock_script,
        configuration,
        xudt_args,
        network_info.clone(),
    );

    builder.add_input(
        TransactionInput {
            live_cell: udt_live_cell[0].clone(),
            since: 0,
        },
        100,
    );

    builder.add_input(
        TransactionInput {
            live_cell: ckb_live_cell[0].clone(),
            since: 0,
        },
        0,
    );

    builder.add_udt_output(&receiver_addr, 50);

    let mut tx_with_groups = builder.build(&Default::default())?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let private_keys = vec![sender_private_key];
    TransactionSigner::new(&network_info).sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_sighash_h256(private_keys)?,
    )?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    // let tx_hash = CkbRpcClient::new(network_info.url.as_str())
    //     .send_transaction(json_tx.inner, None)
    //     .expect("send transaction");
    //
    // println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}
