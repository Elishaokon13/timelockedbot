from flask import Flask, request, jsonify
from stellar_sdk import Keypair, Server, TransactionBuilder, Asset, exceptions
from stellar_sdk.exceptions import Ed25519PublicKeyInvalidError
from bip_utils import Bip39SeedGenerator, Bip39MnemonicValidator, Bip39Languages, Bip32Slip10Ed25519
import logging
from flask_cors import CORS
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import pytz

app = Flask(__name__)
CORS(app)

# Set up logging
logging.basicConfig(level=logging.INFO)

# Stellar Configuration
HORIZON_SERVER = "https://api.mainnet.minepi.com"
NETWORK_PASSPHRASE = "Pi Network"
BASE_FEE = 1000000
server = Server(HORIZON_SERVER)

# Initialize APScheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Shutdown scheduler gracefully on exit
atexit.register(lambda: scheduler.shutdown())

# Derive Stellar keypair from mnemonic
def derive_stellar_keypair(mnemonic):
    try:
        validator = Bip39MnemonicValidator()
        if not validator.IsValid(mnemonic):
            raise ValueError("Invalid mnemonic.")
        seed_bytes = Bip39SeedGenerator(mnemonic, Bip39Languages.ENGLISH).Generate()
        bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed_bytes)
        derived_key = bip32_ctx.DerivePath("m/44'/314159'/0'")
        raw_private_key = derived_key.PrivateKey().Raw().ToBytes()
        keypair = Keypair.from_raw_ed25519_seed(raw_private_key)
        return keypair
    except Exception as e:
        logging.error(f"Key derivation error: {e}")
        raise ValueError(f"Failed to derive keypair: {str(e)}")

# Endpoint to derive keypair from mnemonic
@app.route('/derive_keypair', methods=['POST'])
def derive_keypair():
    try:
        data = request.json
        mnemonic = data['mnemonic'].strip()
        keypair = derive_stellar_keypair(mnemonic)
        try:
            server.load_account(keypair.public_key)
            account_status = "Account exists"
        except exceptions.NotFoundError:
            account_status = "Account does not exist"
        return jsonify({
            "public_key": keypair.public_key,
            "secret_key": keypair.secret,
            "account_status": account_status,
            "message": "Keypair derived successfully"
        })
    except Exception as e:
        logging.error(f"Derivation error: {e}")
        return jsonify({"error": str(e)}), 400

# Function to execute a transaction
def execute_transaction(destination, secret_key, amount):
    try:
        # Validate destination
        try:
            destination_key = Keypair.from_public_key(destination)
            server.load_account(destination)
        except exceptions.NotFoundError:
            logging.error(f"Destination account {destination} does not exist.")
            return {"error": "Destination account not found on the network."}
        except Ed25519PublicKeyInvalidError:
            logging.error(f"Invalid destination public key: {destination}")
            return {"error": "Invalid destination public key format."}

        # Set up sender
        try:
            keypair = Keypair.from_secret(secret_key)
            account = server.load_account(keypair.public_key)
        except exceptions.NotFoundError:
            logging.error(f"Sender account {keypair.public_key} does not exist.")
            return {"error": "Sender account not found on the network."}
        except ValueError:
            logging.error(f"Invalid secret key format.")
            return {"error": "Invalid secret key format."}

        # Build and submit transaction
        transaction = (
            TransactionBuilder(
                source_account=account,
                network_passphrase=NETWORK_PASSPHRASE,
                base_fee=BASE_FEE
            )
            .append_payment_op(
                destination=destination,
                amount=str(amount),
                asset=Asset.native()
            )
            .set_timeout(30)
            .build()
        )
        transaction.sign(keypair)
        response = server.submit_transaction(transaction)
        logging.info(f"Transaction successful: {response['hash']}")
        return {"message": "Transaction successful!", "transaction": response}
    except exceptions.BadRequestError as e:
        logging.error(f"Transaction failed: {e}")
        return {"error": "Transaction failed", "details": e.extras.get('result_codes', {})}
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return {"error": f"Unexpected error: {str(e)}"}

# Endpoint to send payment (immediate)
@app.route('/send_payment', methods=['POST'])
def send_payment():
    try:
        data = request.json
        destination_address = data['destination_address'].strip()
        secret_key = data['secret_key'].strip()
        amount = float(data['amount'])

        result = execute_transaction(destination_address, secret_key, amount)
        if "error" in result:
            return jsonify(result), 400 if "details" in result else 500
        return jsonify(result)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

# Endpoint to schedule payment
@app.route('/schedule_payment', methods=['POST'])
def schedule_payment():
    try:
        data = request.json
        destination_address = data['destination_address'].strip()
        secret_key = data['secret_key'].strip()
        amount = float(data['amount'])
        datetime_str = data['datetime'].strip()

        # Parse datetime assuming it's in WAT (Africa/Lagos, UTC+1)
        naive_scheduled_time = datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M')
        wat_tz = pytz.timezone('Africa/Lagos')  # WAT timezone
        scheduled_time_wat = wat_tz.localize(naive_scheduled_time)
        # Convert to UTC for scheduling
        scheduled_time_utc = scheduled_time_wat.astimezone(pytz.UTC)

        # Log for debugging
        logging.info(f"Received datetime: {datetime_str}")
        logging.info(f"Parsed naive datetime: {naive_scheduled_time}")
        logging.info(f"WAT datetime: {scheduled_time_wat}")
        logging.info(f"UTC datetime: {scheduled_time_utc}")

        # Validate scheduled time is in the future
        current_time_utc = datetime.now(pytz.UTC)
        logging.info(f"Current UTC time: {current_time_utc}")
        if scheduled_time_utc <= current_time_utc:
            logging.warning(f"Scheduled time {scheduled_time_utc} is not in the future.")
            return jsonify({"error": "Scheduled time must be in the future."}), 400

        # Schedule the transaction with APScheduler
        scheduler.add_job(
            execute_transaction,
            'date',
            run_date=scheduled_time_utc,
            args=[destination_address, secret_key, amount],
            id=f"payment_{destination_address}_{datetime_str.replace(':', '-')}"
        )
        logging.info(f"Transaction scheduled for {scheduled_time_utc} (UTC, {scheduled_time_wat} WAT)")
        return jsonify({"message": f"Transaction scheduled for {datetime_str} (WAT)"})
    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        return jsonify({"error": "Invalid date/time format or amount."}), 400
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)