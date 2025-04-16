from flask import Flask, request, jsonify
from stellar_sdk import Keypair, Server, TransactionBuilder, Asset, exceptions
import threading
import time
from datetime import datetime

app = Flask(__name__)

# Pi Network Horizon server and config
HORIZON_SERVER = "https://api.mainnet.minepi.com"
NETWORK_PASSPHRASE = "Pi Network"
BASE_FEE = 1000000
server = Server(HORIZON_SERVER)

# Function to schedule transaction
def schedule_transaction(destination, secret, amount, timestamp):
    delay = (timestamp - datetime.now()).total_seconds()
    if delay > 0:
        time.sleep(delay)

    try:
        destination_key = Keypair.from_public_key(destination)
        server.load_account(destination)
    except Exception as e:
        print(f"Destination error: {e}")
        return

    try:
        sender_keypair = Keypair.from_secret(secret)
        sender_account = server.load_account(sender_keypair.public_key)
    except Exception as e:
        print(f"Sender error: {e}")
        return

    transaction = (
        TransactionBuilder(
            source_account=sender_account,
            network_passphrase=NETWORK_PASSPHRASE,
            base_fee=BASE_FEE
        )
        .append_payment_op(
            destination=destination,
            amount=str(amount),
            asset=Asset.native()  # Native PI token
        )
        .set_timeout(30)
        .build()
    )

    transaction.sign(sender_keypair)

    try:
        response = server.submit_transaction(transaction)
        print("Transaction successful!", response)
    except Exception as e:
        print("Transaction failed:", e)

# Endpoint to schedule a transaction
@app.route('/schedule', methods=['POST'])
def schedule():
    data = request.json
    try:
        destination = data['destination']
        secret = data['secret']
        amount = float(data['amount'])
        datetime_str = data['datetime']
        scheduled_time = datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M')

        threading.Thread(target=schedule_transaction, args=(destination, secret, amount, scheduled_time)).start()
        return jsonify({"message": "Transaction scheduled successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
