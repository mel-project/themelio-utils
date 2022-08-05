use stdcode::StdcodeSerializeExt;
use structopt::StructOpt;
use themelio_stf::melvm::Covenant;
use themelio_structs::{CoinID, Transaction};
use tmelcrypt::Ed25519SK;
#[derive(Debug, StructOpt)]
enum Args {
    /// Generate a ed25519 keypair
    GenerateEd25519,
    /// Hash tool
    Hash(HashOpts),
    /// Generate a CoinID for a reward
    RewardCoin(RewardOpts),
    /// Signs a transaction in hex-encoded form
    SignTx(SignTxOpts),
}

#[derive(Debug, StructOpt)]
struct HashOpts {
    /// The input is a JSON transaction rather than hexadecimal input
    #[structopt(long)]
    json_transaction: bool,

    /// Input to be hashed.
    to_hash: String,
}

#[derive(Debug, StructOpt)]
struct RewardOpts {
    /// Block height
    height: u64,
}

#[derive(Debug, StructOpt)]
struct SignTxOpts {
    /// Position of the signature to place on the transaction. For example, to put the signature in the 1st slot, pass in 0.
    #[structopt(long)]
    posn: usize,
    /// Ed25519 private key, in hexadecimal format.
    #[structopt(long)]
    secret: Ed25519SK,
    /// The transaction to sign. This must be in hexadecimal format.
    tx_to_sign: String,
}

fn print_header(hdr: &str) {
    eprintln!("===== {} =====", hdr);
}

fn main() {
    let args = Args::from_args();
    match args {
        Args::GenerateEd25519 => {
            print_header("NEW ED25519 KEYPAIR");
            let (pk, sk) = tmelcrypt::ed25519_keygen();
            eprintln!("PK = {}", hex::encode(pk.0));
            eprintln!("SK = {}", hex::encode(sk.0));
            let cov = Covenant::std_ed25519_pk_new(pk);
            eprintln!("Address (new covenant): {}", cov.hash().0.to_addr());
        }
        Args::Hash(opts) => {
            let h = if opts.json_transaction {
                let transaction: Transaction = serde_json::from_str(&opts.to_hash).unwrap();
                transaction.hash_nosigs().0
            } else {
                let to_hash = hex::decode(&opts.to_hash).unwrap();
                tmelcrypt::hash_single(&to_hash)
            };
            print_header("HASH OUTPUT");
            eprintln!("{}", hex::encode(&h))
        }
        Args::RewardCoin(opts) => {
            print_header("REWARD PSEUDO-COINID");
            println!("{}", CoinID::proposer_reward(opts.height.into()))
        }
        Args::SignTx(opts) => {
            let mut tx: Transaction = stdcode::deserialize(
                &hex::decode(&opts.tx_to_sign).expect("invalid hex in transaction"),
            )
            .expect("invalid transaction");
            let sig = opts.secret.sign(&tx.hash_nosigs().0);
            // fill zero-valued signatures into the transaction until we can write
            while tx.sigs.get(opts.posn).is_none() {
                tx.sigs.push(vec![]);
            }
            tx.sigs[opts.posn] = sig;
            print_header("SIGNED TRANSACTION");
            println!("{}", hex::encode(tx.stdcode()));
        }
    }
}
