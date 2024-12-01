use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;
use base64::prelude::*;
use indicatif::ProgressBar;
use clap::{command, Parser};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Screen time hash
    #[arg(long)]
    hash: String,

    /// Screen time salt
    #[arg(short, long)]
    salt: String,
}

fn main() {
    let args = Args::parse();

    let hash = args.hash;
    let mut salt = BASE64_STANDARD.decode(args.salt);

    let mut passcode = vec![0; 4];
    let mut out = vec![0u8; 20]; // hmac output buffer, the output is 20 long

    let bar = ProgressBar::new(9999);
    println!("Cracking screen time hash... \n");
    for code in 0..=9999 {
        bar.inc(1);
        // format, so 1 becomes 0001
        let passcode_str = format!("{:04}", code);
        passcode.copy_from_slice(passcode_str.as_bytes());
        // i hate cryptography
        let _ = pbkdf2::<Hmac<Sha1>>(&passcode, &salt.as_mut().unwrap(), 1000, &mut out);

        if BASE64_STANDARD.encode(&out) == hash {
            bar.finish();
            println!("\nYour screen time PIN is: {}", passcode_str);
            break;
        }
    }
}
