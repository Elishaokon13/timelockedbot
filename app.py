from flask import Flask, request, jsonify
from stellar_sdk import Keypair, Server, TransactionBuilder, Asset, exceptions
from stellar_sdk.exceptions import Ed25519PublicKeyInvalidError
from bip_utils import Bip39SeedGenerator, Bip39MnemonicValidator, Bip39Languages, Bip32Slip10Ed25519
import logging
from flask_cors import CORS
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import atexit
import pytz
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import enum

app = Flask(__name__)
CORS(app)

# Set up logging
logging.basicConfig(level=logging.INFO)

# Stellar Configuration
HORIZON_SERVER = "https://api.mainnet.minepi.com"
NETWORK_PASSPHRASE = "Pi Network"
BASE_FEE = 1000000
server = Server(HORIZON_SERVER)

# SQLite Database Setup
engine = create_engine('sqlite:///scheduled_transactions.db')
Base = declarative_base()

# Transaction Status Enum
class TransactionStatus(enum.Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

# Scheduled Transaction Model
class ScheduledTransaction(Base):
    __tablename__ = 'scheduled_transactions'
    id = Column(Integer, primary_key=True)
    job_id = Column(String, unique=True)
    destination_address = Column(String, nullable=False)
    secret_key = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    scheduled_time_wat = Column(DateTime, nullable=False)
    scheduled_time_utc = Column(DateTime, nullable=False)
    status = Column(Enum(TransactionStatus), default=TransactionStatus.PENDING)
    transaction_hash = Column(String, nullable=True)
    error_message = Column(String, nullable=True)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# Initialize APScheduler with SQLite Job Store
scheduler = BackgroundScheduler({
    'apscheduler.jobstores.default': {
        'type': 'sqlalchemy',
        'url': 'sqlite:///scheduled_transactions.db'
    }
})
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
            account_status = "ACTIVE"
        except exceptions.NotFoundError:
            account_status = "INACTIVE"
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
def execute_transaction(destination, secret_key, amount, job_id):
    session = Session()
    try:
        # Validate destination
        try:
            destination_key = Keypair.from_public_key(destination)
            server.load_account(destination)
        except exceptions.NotFoundError:
            logging.error(f"Destination account {destination} does not exist.")
            session.query(ScheduledTransaction).filter_by(job_id=job_id).update({
                'status': TransactionStatus.FAILED,
                'error_message': "Destination account not found on the network."
            })
            session.commit()
            return {"error": "Destination account not found on the network."}

        # Set up sender
        try:
            keypair = Keypair.from_secret(secret_key)
            account = server.load_account(keypair.public_key)
        except exceptions.NotFoundError:
            logging.error(f"Sender account {keypair.public_key} does not exist.")
            session.query(ScheduledTransaction).filter_by(job_id=job_id).update({
                'status': TransactionStatus.FAILED,
                'error_message': "Sender account not found on the network."
            })
            session.commit()
            return {"error": "Sender account not found on the network."}

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

        # Update transaction status
        session.query(ScheduledTransaction).filter_by(job_id=job_id).update({
            'status': TransactionStatus.COMPLETED,
            'transaction_hash': response['hash']
        })
        session.commit()
        return {"message": "Transaction successful!", "transaction": response}
    except exceptions.BadRequestError as e:
        logging.error(f"Transaction failed: {e}")
        session.query(ScheduledTransaction).filter_by(job_id=job_id).update({
            'status': TransactionStatus.FAILED,
            'error_message': f"Transaction failed: {e.extras.get('result_codes', {})}"
        })
        session.commit()
        return {"error": "Transaction failed", "details": e.extras.get('result_codes', {})}
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        session.query(ScheduledTransaction).filter_by(job_id=job_id).update({
            'status': TransactionStatus.FAILED,
            'error_message': f"Unexpected error: {str(e)}"
        })
        session.commit()
        return {"error": f"Unexpected error: {str(e)}"}
    finally:
        session.close()

# Endpoint to send payment (immediate)
@app.route('/send_payment', methods=['POST'])
def send_payment():
    try:
        data = request.json
        destination_address = data['destination_address'].strip()
        secret_key = data['secret_key'].strip()
        amount = float(data['amount'])

        result = execute_transaction(destination_address, secret_key, amount, None)
        if "error" in result:
            return jsonify(result), 400 if "details" in result else 500
        return jsonify(result)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

# Endpoint to schedule payment
@app.route('/schedule_payment', methods=['POST'])
def schedule_payment():
    session = Session()
    try:
        data = request.json
        destination_address = data['destination_address'].strip()
        secret_key = data['secret_key'].strip()
        amount = float(data['amount'])
        datetime_str = data['datetime'].strip()

        # Parse datetime assuming it's in WAT (Africa/Lagos, UTC+1)
        naive_scheduled_time = datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M')
        wat_tz = pytz.timezone('Africa/Lagos')
        scheduled_time_wat = wat_tz.localize(naive_scheduled_time)
        scheduled_time_utc = scheduled_time_wat.astimezone(pytz.UTC)

        # Validate scheduled time is in the future
        current_time_utc = datetime.now(pytz.UTC)
        if scheduled_time_utc <= current_time_utc:
            return jsonify({"error": "Scheduled time must be in the future."}), 400

        # Generate unique job ID
        job_id = f"payment_{destination_address}_{datetime_str.replace(':', '-')}_{int(current_time_utc.timestamp())}"

        # Save transaction details
        scheduled_tx = ScheduledTransaction(
            job_id=job_id,
            destination_address=destination_address,
            secret_key=secret_key,
            amount=amount,
            scheduled_time_wat=scheduled_time_wat,
            scheduled_time_utc=scheduled_time_utc,
            status=TransactionStatus.PENDING
        )
        session.add(scheduled_tx)
        session.commit()

        # Schedule the transaction
        scheduler.add_job(
            execute_transaction,
            'date',
            run_date=scheduled_time_utc,
            args=[destination_address, secret_key, amount, job_id],
            id=job_id
        )
        logging.info(f"Transaction scheduled for {scheduled_time_utc} (UTC, {scheduled_time_wat} WAT)")
        return jsonify({"message": f"Transaction scheduled for {datetime_str} (WAT)"})
    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        return jsonify({"error": "Invalid date/time format or amount."}), 400
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        session.close()

# Endpoint to get scheduled transactions
@app.route('/get_scheduled_transactions', methods=['GET'])
def get_scheduled_transactions():
    session = Session()
    try:
        transactions = session.query(ScheduledTransaction).all()
        result = [{
            "job_id": tx.job_id,
            "destination_address": tx.destination_address,
            "amount": tx.amount,
            "scheduled_time_wat": tx.scheduled_time_wat.strftime('%Y-%m-%d %H:%M:%S %Z'),
            "status": tx.status.value,
            "transaction_hash": tx.transaction_hash,
            "error_message": tx.error_message
        } for tx in transactions]
        return jsonify({"transactions": result})
    except Exception as e:
        logging.error(f"Error fetching transactions: {e}")
        return jsonify({"error": f"Error fetching transactions: {str(e)}"}), 500
    finally:
        session.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)