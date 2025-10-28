"""
Flask Web Application with JWT Authentication and Authorization
Simulates e-commerce/banking authentication with digital signatures
"""

from flask import Flask, request, jsonify, render_template_string
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
import hashlib
import datetime
from digital_signature import RSADigitalSignature
import json
import base64

app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = 'your-secret-string-here-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)

jwt = JWTManager(app)

# In-memory storage (in production, use a database)
users = {
    'customer1': {
        'password': hashlib.sha256('password123'.encode()).hexdigest(),
        'role': 'customer',
        'account_balance': 5000.0,
        'public_key': None
    },
    'bank_admin': {
        'password': hashlib.sha256('admin123'.encode()).hexdigest(),
        'role': 'admin',
        'account_balance': None,
        'public_key': None
    },
    'merchant1': {
        'password': hashlib.sha256('merchant123'.encode()).hexdigest(),
        'role': 'merchant',
        'account_balance': 10000.0,
        'public_key': None
    }
}

# Transaction log
transactions = []

# Global RSA instance for demo purposes
rsa_signature = RSADigitalSignature()

# HTML Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Banking System</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .main-container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 12px; 
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white; 
            padding: 20px 30px; 
            text-align: center;
        }
        .header h1 { font-size: 2.2em; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 1.1em; }
        
        .content-grid { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 30px; 
            padding: 30px;
        }
        
        .left-panel, .right-panel { 
            background: #f8f9fa; 
            padding: 25px; 
            border-radius: 8px; 
            border: 1px solid #e9ecef;
        }
        
        .section-title { 
            color: #2c3e50; 
            font-size: 1.4em; 
            margin-bottom: 20px; 
            padding-bottom: 10px; 
            border-bottom: 2px solid #3498db;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .horizontal-form { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 15px; 
            align-items: end;
        }
        
        .form-group { 
            margin-bottom: 15px; 
        }
        
        .form-group.full-width { 
            grid-column: span 2; 
        }
        
        label { 
            display: block; 
            margin-bottom: 5px; 
            font-weight: 600; 
            color: #495057;
        }
        
        input, textarea, select { 
            width: 100%; 
            padding: 12px; 
            border: 2px solid #e9ecef; 
            border-radius: 6px; 
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        
        input:focus, textarea:focus { 
            outline: none; 
            border-color: #3498db; 
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
        }
        
        button { 
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white; 
            padding: 12px 24px; 
            border: none; 
            border-radius: 6px; 
            cursor: pointer; 
            font-weight: 600;
            transition: all 0.3s ease;
            font-size: 14px;
        }
        
        button:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(52, 152, 219, 0.3);
        }
        
        button.secondary { 
            background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%);
        }
        
        button.success { 
            background: linear-gradient(135deg, #27ae60 0%, #229954 100%);
        }
        
        button.danger { 
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        }
        
        .success { 
            color: #155724; 
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            padding: 15px; 
            border-radius: 6px; 
            margin: 15px 0; 
            border-left: 4px solid #28a745;
        }
        
        .error { 
            color: #721c24; 
            background: linear-gradient(135deg, #f8d7da 0%, #f1b0b7 100%);
            padding: 15px; 
            border-radius: 6px; 
            margin: 15px 0; 
            border-left: 4px solid #dc3545;
        }
        
        .info-box { 
            background: linear-gradient(135deg, #e7f3ff 0%, #cce7ff 100%);
            border: 1px solid #bee5eb; 
            border-radius: 6px; 
            padding: 20px; 
            margin: 20px 0;
            border-left: 4px solid #17a2b8;
        }
        
        .info-box h4 { 
            color: #0c5460; 
            margin-bottom: 10px; 
        }
        
        .info-box ul { 
            margin-left: 20px; 
        }
        
        .info-box li { 
            margin: 5px 0; 
            color: #0c5460;
        }
        
        .transaction { 
            background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
            padding: 20px; 
            margin: 15px 0; 
            border-radius: 8px; 
            border-left: 4px solid #007bff;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            transition: transform 0.2s ease;
        }
        
        .transaction:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .transaction-grid { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 10px; 
            font-size: 14px;
        }
        
        .transaction strong { 
            color: #2c3e50; 
        }
        
        .status-verified { 
            color: #28a745; 
            font-weight: bold; 
        }
        
        .status-pending { 
            color: #ffc107; 
            font-weight: bold; 
        }
        
        .signature-display { 
            background: #f1f3f4; 
            padding: 10px; 
            border-radius: 4px; 
            font-family: monospace; 
            font-size: 12px; 
            word-break: break-all;
            margin: 10px 0;
        }
        
        .button-group { 
            display: flex; 
            gap: 10px; 
            flex-wrap: wrap;
        }
        
        .full-width-section { 
            grid-column: span 2; 
            margin-top: 20px;
        }
        
        .emoji { 
            font-size: 1.2em; 
        }
        
        @media (max-width: 768px) {
            .content-grid { 
                grid-template-columns: 1fr; 
                gap: 20px; 
                padding: 20px;
            }
            .horizontal-form { 
                grid-template-columns: 1fr; 
            }
            .form-group.full-width { 
                grid-column: span 1; 
            }
        }
    </style>
</head>
<body>
    <div class="main-container">
        <div class="header">
            <h1><span class="emoji">🏦</span> Secure Digital Banking System</h1>
            <p>Demonstrating digital signatures, authentication, and authorization in banking/e-commerce</p>
        </div>
        
        <div class="content-grid">
            <!-- Left Panel: Authentication & Users -->
            <div class="left-panel">
                <h3 class="section-title">
                    <span class="emoji">👥</span> Authentication
                </h3>
                
                <div class="info-box">
                    <h4>Sample Users:</h4>
                    <ul>
                        <li><strong>customer1</strong> / password123 (Customer)</li>
                        <li><strong>bank_admin</strong> / admin123 (Administrator)</li>
                        <li><strong>merchant1</strong> / merchant123 (Merchant)</li>
                    </ul>
                </div>
                
                <div class="horizontal-form">
                    <div class="form-group">
                        <label>Username:</label>
                        <input type="text" id="username" placeholder="Enter username">
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input type="password" id="password" placeholder="Enter password">
                    </div>
                    <div class="form-group">
                        <button onclick="login()">Login</button>
                    </div>
                </div>
                
                <div id="result"></div>
                
                <!-- Transaction Section -->
                <div id="transaction-section" style="display:none;">
                    <h3 class="section-title">
                        <span class="emoji">💳</span> Secure Transaction
                    </h3>
                    
                    <div class="horizontal-form">
                        <div class="form-group">
                            <label>Recipient:</label>
                            <input type="text" id="recipient" placeholder="Recipient username">
                        </div>
                        <div class="form-group">
                            <label>Amount:</label>
                            <input type="number" id="amount" placeholder="Amount" step="0.01">
                        </div>
                        <div class="form-group">
                            <button class="success" onclick="createTransaction()">Create Signed Transaction</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Right Panel: Digital Signatures -->
            <div class="right-panel">
                <h3 class="section-title">
                    <span class="emoji">�</span> Digital Signature Testing
                </h3>
                
                <div class="form-group">
                    <label>Message to Sign:</label>
                    <textarea id="message" rows="3" placeholder="Enter message to digitally sign">Transaction: Transfer $500 from Account A to Account B</textarea>
                </div>
                
                <div class="button-group">
                    <button onclick="generateSignature()">Generate Digital Signature</button>
                    <button class="secondary" onclick="verifySignature()">Verify Signature</button>
                </div>
                
                <div id="signature-result"></div>
            </div>
            
            <!-- Full Width Transactions Section -->
            <div class="full-width-section">
                <div id="transactions-list"></div>
            </div>
        </div>
    </div>

    <script>
        let authToken = '';
        let currentSignature = '';
        let currentMessage = '';
        
        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    authToken = data.access_token;
                    document.getElementById('result').innerHTML = 
                        `<div class="success"><span class="emoji">✅</span> Login successful! Role: ${data.role}</div>`;
                    document.getElementById('transaction-section').style.display = 'block';
                    loadTransactions();
                } else {
                    document.getElementById('result').innerHTML = 
                        `<div class="error"><span class="emoji">❌</span> ${data.message}</div>`;
                }
            } catch (error) {
                document.getElementById('result').innerHTML = 
                    `<div class="error">❌ Error: ${error.message}</div>`;
            }
        }
        
        async function generateSignature() {
            const message = document.getElementById('message').value;
            currentMessage = message;
            
            try {
                const response = await fetch('/generate-signature', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message})
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    currentSignature = data.signature;
                    document.getElementById('signature-result').innerHTML = 
                        `<div class="success">
                            <h4><span class="emoji">✅</span> Digital Signature Generated</h4>
                            <div class="transaction-grid">
                                <div><strong>Message:</strong> ${message}</div>
                                <div><strong>Public Key Fingerprint:</strong> ${data.public_key_fingerprint}</div>
                            </div>
                            <div class="signature-display">
                                <strong>Signature:</strong> ${data.signature.substring(0, 100)}...
                            </div>
                        </div>`;
                } else {
                    document.getElementById('signature-result').innerHTML = 
                        `<div class="error">❌ ${data.message}</div>`;
                }
            } catch (error) {
                document.getElementById('signature-result').innerHTML = 
                    `<div class="error">❌ Error: ${error.message}</div>`;
            }
        }
        
        async function verifySignature() {
            if (!currentSignature || !currentMessage) {
                document.getElementById('signature-result').innerHTML = 
                    `<div class="error">❌ Please generate a signature first</div>`;
                return;
            }
            
            try {
                const response = await fetch('/verify-signature', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        message: currentMessage,
                        signature: currentSignature
                    })
                });
                
                const data = await response.json();
                
                if (response.ok && data.valid) {
                    document.getElementById('signature-result').innerHTML += 
                        `<div class="success"><span class="emoji">✅</span> Signature verification successful! Message integrity confirmed.</div>`;
                } else {
                    document.getElementById('signature-result').innerHTML += 
                        `<div class="error"><span class="emoji">❌</span> Signature verification failed! Message may have been tampered with.</div>`;
                }
            } catch (error) {
                document.getElementById('signature-result').innerHTML += 
                    `<div class="error">❌ Error: ${error.message}</div>`;
            }
        }
        
        async function createTransaction() {
            if (!authToken) {
                alert('Please login first');
                return;
            }
            
            const recipient = document.getElementById('recipient').value;
            const amount = parseFloat(document.getElementById('amount').value);
            
            try {
                const response = await fetch('/transaction', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: JSON.stringify({recipient, amount})
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    document.getElementById('result').innerHTML = 
                        `<div class="success"><span class="emoji">✅</span> Transaction created successfully!</div>`;
                    loadTransactions();
                } else {
                    document.getElementById('result').innerHTML = 
                        `<div class="error"><span class="emoji">❌</span> ${data.message}</div>`;
                }
            } catch (error) {
                document.getElementById('result').innerHTML = 
                    `<div class="error">❌ Error: ${error.message}</div>`;
            }
        }
        
        async function loadTransactions() {
            if (!authToken) return;
            
            try {
                const response = await fetch('/transactions', {
                    headers: {'Authorization': `Bearer ${authToken}`}
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    let html = '<h3 class="section-title"><span class="emoji">📊</span> Recent Transactions</h3>';
                    data.transactions.forEach(tx => {
                        html += `
                            <div class="transaction">
                                <div class="transaction-grid">
                                    <div><strong>Transaction ID:</strong> ${tx.id}</div>
                                    <div><strong>Amount:</strong> $${tx.amount}</div>
                                    <div><strong>From:</strong> ${tx.from}</div>
                                    <div><strong>To:</strong> ${tx.to}</div>
                                    <div><strong>Timestamp:</strong> ${tx.timestamp}</div>
                                    <div><strong>Status:</strong> <span class="status-${tx.verified ? 'verified' : 'pending'}">${tx.verified ? '✅ Verified' : '⏳ Pending'}</span></div>
                                </div>
                                <div class="signature-display">
                                    <strong>Signature:</strong> ${tx.signature.substring(0, 80)}...
                                </div>
                            </div>
                        `;
                    });
                    document.getElementById('transactions-list').innerHTML = html;
                }
            } catch (error) {
                console.error('Error loading transactions:', error);
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and return JWT token
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    
    # Hash the provided password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Check credentials
    if username in users and users[username]['password'] == password_hash:
        # Create JWT token with user info
        additional_claims = {
            'role': users[username]['role'],
            'username': username
        }
        access_token = create_access_token(
            identity=username,
            additional_claims=additional_claims
        )
        
        return jsonify({
            'access_token': access_token,
            'role': users[username]['role'],
            'message': 'Login successful'
        }), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/generate-signature', methods=['POST'])
def generate_signature():
    """
    Generate digital signature for a message
    """
    data = request.get_json()
    message = data.get('message')
    
    if not message:
        return jsonify({'message': 'Message is required'}), 400
    
    try:
        # Generate keys if not exists
        if not rsa_signature.private_key:
            rsa_signature.generate_key_pair()
        
        # Sign the message
        signature = rsa_signature.sign_message(message)
        
        # Get public key fingerprint for identification
        public_key_pem = rsa_signature.get_public_key_pem()
        public_key_fingerprint = hashlib.sha256(public_key_pem.encode()).hexdigest()[:16]
        
        return jsonify({
            'signature': signature,
            'public_key_fingerprint': public_key_fingerprint,
            'message': 'Signature generated successfully'
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error generating signature: {str(e)}'}), 500

@app.route('/verify-signature', methods=['POST'])
def verify_signature():
    """
    Verify digital signature
    """
    data = request.get_json()
    message = data.get('message')
    signature = data.get('signature')
    
    if not message or not signature:
        return jsonify({'message': 'Message and signature are required'}), 400
    
    try:
        # Verify the signature
        is_valid = rsa_signature.verify_signature(message, signature)
        
        return jsonify({
            'valid': is_valid,
            'message': 'Signature verified' if is_valid else 'Signature verification failed'
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error verifying signature: {str(e)}'}), 500

@app.route('/transaction', methods=['POST'])
@jwt_required()
def create_transaction():
    """
    Create a digitally signed transaction (requires authentication)
    """
    current_user = get_jwt_identity()
    claims = get_jwt()
    
    data = request.get_json()
    recipient = data.get('recipient')
    amount = data.get('amount')
    
    if not recipient or not amount:
        return jsonify({'message': 'Recipient and amount are required'}), 400
    
    if recipient not in users:
        return jsonify({'message': 'Recipient not found'}), 404
    
    if amount <= 0:
        return jsonify({'message': 'Amount must be positive'}), 400
    
    # Check sufficient balance for customers
    if users[current_user]['role'] == 'customer':
        if users[current_user]['account_balance'] < amount:
            return jsonify({'message': 'Insufficient balance'}), 400
    
    try:
        # Create transaction message
        transaction_id = f"TX{len(transactions) + 1:06d}"
        timestamp = datetime.datetime.now().isoformat()
        
        transaction_message = f"TRANSACTION|{transaction_id}|{current_user}|{recipient}|{amount}|{timestamp}"
        
        # Generate digital signature for the transaction
        if not rsa_signature.private_key:
            rsa_signature.generate_key_pair()
        
        signature = rsa_signature.sign_message(transaction_message)
        
        # Create transaction record
        transaction = {
            'id': transaction_id,
            'from': current_user,
            'to': recipient,
            'amount': amount,
            'timestamp': timestamp,
            'signature': signature,
            'message': transaction_message,
            'verified': True
        }
        
        # Update balances (simplified)
        if users[current_user]['role'] == 'customer':
            users[current_user]['account_balance'] -= amount
            users[recipient]['account_balance'] += amount
        
        # Store transaction
        transactions.append(transaction)
        
        return jsonify({
            'transaction_id': transaction_id,
            'signature': signature,
            'message': 'Transaction created and signed successfully'
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error creating transaction: {str(e)}'}), 500

@app.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    """
    Get transaction history (requires authentication)
    """
    current_user = get_jwt_identity()
    claims = get_jwt()
    
    # Filter transactions based on user role
    if claims['role'] == 'admin':
        # Admin can see all transactions
        user_transactions = transactions
    else:
        # Users can only see their own transactions
        user_transactions = [tx for tx in transactions if tx['from'] == current_user or tx['to'] == current_user]
    
    return jsonify({
        'transactions': user_transactions,
        'count': len(user_transactions)
    }), 200

@app.route('/verify-transaction/<transaction_id>', methods=['GET'])
@jwt_required()
def verify_transaction(transaction_id):
    """
    Verify a specific transaction's digital signature
    """
    # Find transaction
    transaction = next((tx for tx in transactions if tx['id'] == transaction_id), None)
    
    if not transaction:
        return jsonify({'message': 'Transaction not found'}), 404
    
    try:
        # Verify the transaction signature
        is_valid = rsa_signature.verify_signature(transaction['message'], transaction['signature'])
        
        # Update transaction verification status
        transaction['verified'] = is_valid
        
        return jsonify({
            'transaction_id': transaction_id,
            'verified': is_valid,
            'message': 'Transaction signature verified' if is_valid else 'Transaction signature invalid'
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error verifying transaction: {str(e)}'}), 500

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """
    Get user profile information (requires authentication)
    """
    current_user = get_jwt_identity()
    claims = get_jwt()
    
    user_info = {
        'username': current_user,
        'role': claims['role'],
        'account_balance': users[current_user]['account_balance']
    }
    
    return jsonify(user_info), 200

# Error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'message': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'message': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'message': 'Authorization token is required'}), 401

if __name__ == '__main__':
    print("🏦 Starting Secure Digital Banking System...")
    print("=" * 50)
    print("Features:")
    print("✓ RSA Digital Signatures")
    print("✓ JWT Authentication")
    print("✓ Role-based Authorization")
    print("✓ Secure Transaction Processing")
    print("=" * 50)
    print("Access the application at: http://localhost:5000")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
