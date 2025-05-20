from flask import Flask, request, jsonify, g, abort
import pickle
import numpy as np
import os
import time
import ssl
import uuid
import re
import json
import bleach
from datetime import datetime, timedelta
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import hashlib
import hmac
import redis
import secrets
from werkzeug.middleware.proxy_fix import ProxyFix
import sqlalchemy
from sqlalchemy import Column, String, Integer, Float, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import text
import jwt

# Initialize Flask with secure configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JSON_SORT_KEYS'] = False  # Preserve order in responses
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Handle reverse proxies correctly for rate limiting
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


# Configure logging with sensitive data filtering
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = re.sub(r'(api_key|password|token|secret)=([^&\s]+)', r'\1=********', record.msg)
        return True


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [request_id:%(request_id)s] - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)
logger.addFilter(SensitiveDataFilter())

# Set up rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour", "5 per minute"],
    storage_uri=os.environ.get('REDIS_URL')
)

# Redis for distributed rate limiting and cache
REDIS_URL = os.environ.get('REDIS_URL')
if REDIS_URL:
    try:
        redis_client = redis.from_url(REDIS_URL)
        logger.info("Redis connection established")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        redis_client = None
else:
    redis_client = None

# Database setup for audit logs and user management
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    try:
        # Use best practices for SQLAlchemy connection
        engine = create_engine(
            DATABASE_URL,
            pool_pre_ping=True,  # Verify connections before use
            pool_recycle=3600,  # Recycle connections hourly
            connect_args={"connect_timeout": 5}  # Connection timeout
        )
        Base = declarative_base()


        class AuditLog(Base):
            __tablename__ = 'audit_logs'
            id = Column(Integer, primary_key=True)
            request_id = Column(String(36), nullable=False)
            timestamp = Column(DateTime, nullable=False)
            client_ip = Column(String(45), nullable=False)
            user_id = Column(String(36), nullable=True)
            endpoint = Column(String(100), nullable=False)
            method = Column(String(10), nullable=False)
            status_code = Column(Integer, nullable=False)
            request_data = Column(String(1000), nullable=True)


        class ApiUser(Base):
            __tablename__ = 'api_users'
            id = Column(String(36), primary_key=True)
            api_key = Column(String(64), unique=True, nullable=False)
            api_secret = Column(String(64), nullable=False)
            name = Column(String(100), nullable=False)
            email = Column(String(100), nullable=False)
            is_active = Column(Integer, default=1)
            rate_limit = Column(String(50), default="100 per day")
            created_at = Column(DateTime, default=datetime.utcnow)
            last_access = Column(DateTime, nullable=True)


        # Create tables if they don't exist
        Base.metadata.create_all(engine)
        SessionMaker = sessionmaker(bind=engine)
        logger.info("Database connection established")
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        DATABASE_URL = None
        SessionMaker = None
else:
    DATABASE_URL = None
    SessionMaker = None

# Load the model once when the application starts
MODEL_PATH = os.environ.get('MODEL_PATH', 'solar_optimization_model.pkl')

try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    logger.info(f"Successfully loaded model from {MODEL_PATH}")
except Exception as e:
    logger.error(f"Error loading model: {e}")
    model = None

# Security constants
MASTER_API_KEY = os.environ.get('MASTER_API_KEY')
MASTER_API_SECRET = os.environ.get('MASTER_API_SECRET')
JWT_SECRET = os.environ.get('JWT_SECRET', app.config['SECRET_KEY'])
REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', '60'))  # Seconds
MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', '10240'))  # 10KB limit
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Input validation patterns
PATTERNS = {
    'datetime': re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'),
    'latitude': re.compile(r'^-?(\d{1,2}(\.\d+)?)$'),  # -90 to 90
    'longitude': re.compile(r'^-?(\d{1,3}(\.\d+)?)$'),  # -180 to 180
    'number': re.compile(r'^-?\d+(\.\d+)?$')
}

# Initialize request tracking
failed_attempts = {}
request_logs = {}


# Request context middleware
@app.before_request
def before_request():
    g.start_time = time.time()
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))

    # Add request ID to logger
    logging.LoggerAdapter(logger, {'request_id': g.request_id})

    # Check for suspicious request indicators - potential DoS or injection
    if _is_suspicious_request(request):
        logger.warning(f"Suspicious request detected from {get_remote_address()}")
        abort(403)

    # Validate content type for POST requests
    if request.method == 'POST' and request.path != '/health':
        if request.content_type != 'application/json':
            return jsonify({"error": "Content-Type must be application/json"}), 415

    # Initialize user data
    g.user_id = None


# OWASP A01:2021 - Broken Access Control protection
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_remote_address()

        # Track request in memory or Redis
        request_id = g.request_id
        request_logs[request_id] = {
            'ip': client_ip,
            'path': request.path,
            'method': request.method,
            'timestamp': datetime.utcnow(),
            'user_id': None
        }

        # Check if IP is blocked due to too many failed attempts
        if _is_ip_blocked(client_ip):
            logger.warning(f"Blocked request from {client_ip}")
            return jsonify({"error": "Too many failed attempts. Try again later."}), 429

        # Validate API key
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            _register_auth_failure(client_ip)
            return jsonify({"error": "API key is required"}), 401

        # OWASP A07:2021 - Identification and Authentication Failures protection
        # Check if API key exists in database or is the master key
        user = None
        if api_key != MASTER_API_KEY:
            if DATABASE_URL:
                try:
                    session = SessionMaker()
                    user = session.query(ApiUser).filter_by(api_key=api_key, is_active=1).first()
                    session.close()

                    if not user:
                        _register_auth_failure(client_ip)
                        return jsonify({"error": "Invalid API key"}), 403

                    # Update last access
                    session = SessionMaker()
                    user.last_access = datetime.utcnow()
                    session.commit()
                    session.close()

                    # Store user ID for audit log
                    g.user_id = user.id
                    request_logs[request_id]['user_id'] = user.id

                    # Use user-specific rate limits
                    limiter.limit(user.rate_limit)(f)

                except Exception as e:
                    logger.error(f"Database error during authentication: {e}")
                    return jsonify({"error": "Authentication service unavailable"}), 500
            else:
                if api_key != MASTER_API_KEY:
                    _register_auth_failure(client_ip)
                    return jsonify({"error": "Invalid API key"}), 403

        # Validate timestamp to prevent replay attacks
        timestamp = request.headers.get('X-Timestamp')
        if not timestamp:
            return jsonify({"error": "Timestamp header is required"}), 400

        try:
            request_time = int(timestamp)
            current_time = int(time.time())

            if abs(current_time - request_time) > REQUEST_TIMEOUT:
                return jsonify({"error": "Request timestamp expired"}), 400
        except ValueError:
            return jsonify({"error": "Invalid timestamp format"}), 400

        # OWASP A03:2021 - Injection protection
        # Validate HMAC signature for content integrity using user-specific or master secret
        api_secret = MASTER_API_SECRET
        if user and hasattr(user, 'api_secret'):
            api_secret = user.api_secret

        if api_secret:
            signature = request.headers.get('X-Signature')
            if not signature:
                return jsonify({"error": "Request signature is required"}), 400

            # Recreate the signature from request body
            body = request.get_data()
            expected_signature = hmac.new(
                api_secret.encode('utf-8'),
                f"{timestamp}{body}".encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_signature):
                _register_auth_failure(client_ip)
                return jsonify({"error": "Invalid request signature"}), 403

        return f(*args, **kwargs)

    return decorated_function


# OWASP A05:2021 - Security Misconfiguration protection
def _is_suspicious_request(request):
    """Check for suspicious request patterns"""
    # Check common SQL injection patterns
    sql_patterns = [
        "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "--", "/*",
        "*/", "EXEC", "xp_", "sp_", "WAITFOR", "1=1", "OR 1=1"
    ]

    # Check common XSS patterns
    xss_patterns = [
        "<script>", "javascript:", "onerror=", "onload=", "eval(", "alert(", "document.cookie",
        "document.location", "<img", "<iframe", "data:text/html", "vbscript:",
        "expression(", "url(", "fromCharCode"
    ]

    # Check URL for suspicious patterns
    url = request.url.upper()
    for pattern in sql_patterns + xss_patterns:
        if pattern.upper() in url:
            return True

    # Check headers for suspicious patterns
    for header in request.headers.values():
        header_value = str(header).upper()
        for pattern in sql_patterns + xss_patterns:
            if pattern.upper() in header_value:
                return True

    # Check POST data if present
    if request.method == 'POST' and request.is_json:
        try:
            data = request.get_json(silent=True)
            if data:
                data_str = json.dumps(data).upper()
                for pattern in sql_patterns + xss_patterns:
                    if pattern.upper() in data_str:
                        return True
        except:
            pass

    return False


def _is_ip_blocked(ip):
    """Check if IP is blocked due to suspicious activity"""
    if redis_client:
        block_key = f"block:{ip}"
        return redis_client.exists(block_key)
    elif ip in failed_attempts:
        return failed_attempts[ip]['count'] >= 5 and \
            time.time() - failed_attempts[ip]['timestamp'] < 300  # 5 minutes block
    return False


def _register_auth_failure(ip):
    """Track failed authentication attempts"""
    if redis_client:
        key = f"auth_fail:{ip}"
        count = redis_client.incr(key)
        redis_client.expire(key, 300)  # 5 minutes expiry

        if count >= 5:
            block_key = f"block:{ip}"
            redis_client.setex(block_key, 300, 1)  # Block for 5 minutes
    else:
        if ip not in failed_attempts:
            failed_attempts[ip] = {'count': 1, 'timestamp': time.time()}
        else:
            failed_attempts[ip]['count'] += 1
            failed_attempts[ip]['timestamp'] = time.time()

    logger.warning(f"Authentication failure from IP {ip}")


# OWASP A10:2021 - Server-Side Request Forgery protection
def _sanitize_input(data):
    """Sanitize and validate input data"""
    if not isinstance(data, dict):
        raise ValueError("Input must be a JSON object")

    # Create a new sanitized dictionary
    sanitized = {}

    # Validate required fields
    required_fields = [
        'datetime', 'latitude', 'longitude', 'altitude',
        'ambient_temperature', 'wind_speed', 'ghi', 'dhi', 'dni'
    ]

    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")

    # Validate and sanitize datetime
    if not PATTERNS['datetime'].match(data['datetime']):
        raise ValueError("Invalid datetime format. Use ISO format (YYYY-MM-DDTHH:MM:SSZ)")
    sanitized['datetime'] = data['datetime']

    # Validate latitude (-90 to 90)
    if not PATTERNS['latitude'].match(str(data['latitude'])):
        raise ValueError("Invalid latitude format")
    lat = float(data['latitude'])
    if lat < -90 or lat > 90:
        raise ValueError("Latitude must be between -90 and 90")
    sanitized['latitude'] = lat

    # Validate longitude (-180 to 180)
    if not PATTERNS['longitude'].match(str(data['longitude'])):
        raise ValueError("Invalid longitude format")
    lon = float(data['longitude'])
    if lon < -180 or lon > 180:
        raise ValueError("Longitude must be between -180 and 180")
    sanitized['longitude'] = lon

    # Validate remaining numeric fields
    numeric_fields = [
        'altitude', 'ambient_temperature', 'wind_speed', 'ghi', 'dhi', 'dni'
    ]

    for field in numeric_fields:
        if not PATTERNS['number'].match(str(data[field])):
            raise ValueError(f"Invalid {field} format")
        sanitized[field] = float(data[field])

    return sanitized


# OWASP A02:2021 - Cryptographic Failures protection
def preprocess_data(data):
    """
    Preprocess sanitized data to match the model's expected input format
    """
    try:
        # Parse datetime
        dt = datetime.fromisoformat(data['datetime'].replace('Z', '+00:00'))

        # Extract relevant features for the model
        features = [
            dt.hour,  # Hour of day
            dt.month,  # Month of year
            data['latitude'],  # Latitude
            data['longitude'],  # Longitude
            data['altitude'],  # Altitude
            data['ambient_temperature'],  # Ambient temperature
            data['wind_speed'],  # Wind speed
            data['ghi'],  # Global Horizontal Irradiance
            data['dhi'],  # Diffuse Horizontal Irradiance
            data['dni']  # Direct Normal Irradiance
        ]

        return np.array(features).reshape(1, -1)  # Reshape for single prediction

    except KeyError as e:
        raise ValueError(f"Missing required field: {e}")
    except Exception as e:
        raise ValueError(f"Error preprocessing data: {e}")


# OWASP A01:2021 protection - Broken Access Control for admin functions
@app.route('/admin/users', methods=['GET'])
@limiter.limit("5 per minute")
@require_api_key
def list_users():
    # Only allow master API key to access admin functions
    if request.headers.get('X-API-Key') != MASTER_API_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    if not DATABASE_URL or not SessionMaker:
        return jsonify({"error": "Database not configured"}), 500

    try:
        session = SessionMaker()
        users = session.query(ApiUser).all()
        user_list = []

        for user in users:
            user_list.append({
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "is_active": bool(user.is_active),
                "rate_limit": user.rate_limit,
                "created_at": user.created_at.isoformat(),
                "last_access": user.last_access.isoformat() if user.last_access else None
            })

        session.close()
        return jsonify({"users": user_list})
    except Exception as e:
        logger.error(f"Database error: {e}")
        return jsonify({"error": "Database error"}), 500


# OWASP A06:2021 - Vulnerable and Outdated Components protection
# Main prediction endpoint with proper input validation
@app.route('/predict', methods=['POST'])
@limiter.limit("10 per minute")  # Stricter rate limit for prediction endpoint
@require_api_key
def predict():
    if not model:
        return jsonify({"error": "Model not loaded"}), 500

    # Get data from request
    start_time = time.time()
    if time.time() - start_time > 5:  # Timeout for request processing
        return jsonify({"error": "Request processing timeout"}), 408

    # OWASP A03:2021 - Injection & A10:2021 - SSRF protection
    # Careful parsing and validation of input
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        # Sanitize and validate input
        sanitized_data = _sanitize_input(data)

        # Preprocess data
        features = preprocess_data(sanitized_data)

        # Make prediction
        prediction = model.predict(features)[0]

        # Include request ID for audit trail
        response_data = {
            "optimal_tilt": float(prediction[0]),
            "optimal_azimuth": float(prediction[1]),
            "request_id": g.request_id,
            "timestamp": int(time.time())
        }

        # Log successful prediction
        logger.info(f"Successful prediction: {g.request_id}")

        # Add to audit log
        if DATABASE_URL and SessionMaker:
            try:
                session = SessionMaker()
                log_entry = AuditLog(
                    request_id=g.request_id,
                    timestamp=datetime.utcnow(),
                    client_ip=get_remote_address(),
                    user_id=g.user_id,
                    endpoint='/predict',
                    method='POST',
                    status_code=200,
                    request_data=json.dumps(sanitized_data)
                )
                session.add(log_entry)
                session.commit()
                session.close()
            except Exception as e:
                logger.error(f"Failed to log to database: {e}")

        return jsonify(response_data)

    except ValueError as e:
        error_message = str(e)
        logger.warning(f"Input validation error: {error_message}")
        return jsonify({"error": error_message}), 400
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/health', methods=['GET'])
@limiter.limit("30 per minute")
def health_check():
    # Generate a JWT for security checks
    token = jwt.encode(
        {"check": "health", "time": time.time()},
        JWT_SECRET,
        algorithm="HS256"
    )

    health_data = {
        "status": "healthy" if model else "unhealthy",
        "model_loaded": model is not None,
        "timestamp": int(time.time()),
        "request_id": g.request_id,
        "security_token": token
    }

    # Add database status if available
    if DATABASE_URL:
        try:
            session = SessionMaker()
            session.execute(text("SELECT 1"))
            session.close()
            health_data["database"] = "connected"
        except:
            health_data["database"] = "error"
    else:
        health_data["database"] = "not_configured"

    # Add redis status if available
    if redis_client:
        try:
            redis_client.ping()
            health_data["redis"] = "connected"
        except:
            health_data["redis"] = "error"
    else:
        health_data["redis"] = "not_configured"

    return jsonify(health_data)


# OWASP A04:2021 - Insecure Design protection
# Add security headers to all responses
@app.after_request
def add_security_headers(response):
    # Add request ID for tracking
    response.headers['X-Request-ID'] = g.request_id

    # Security headers
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    # Log response time and status code
    if hasattr(g, 'start_time'):
        process_time = time.time() - g.start_time
        logger.info(f"Request completed in {process_time:.4f}s with status {response.status_code}")

    # Record in audit log
    if hasattr(g, 'request_id') and g.request_id in request_logs:
        request_info = request_logs[g.request_id]
        if DATABASE_URL and SessionMaker:
            try:
                session = SessionMaker()
                log_entry = AuditLog(
                    request_id=g.request_id,
                    timestamp=datetime.utcnow(),
                    client_ip=request_info['ip'],
                    user_id=request_info['user_id'],
                    endpoint=request_info['path'],
                    method=request_info['method'],
                    status_code=response.status_code,
                    request_data=None
                )
                session.add(log_entry)
                session.commit()
                session.close()
            except Exception as e:
                logger.error(f"Failed to log to database: {e}")

        # Clean up the request log
        request_logs.pop(g.request_id, None)

    return response


# Error handlers for various HTTP status codes
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad request", "request_id": getattr(g, 'request_id', 'unknown')}), 400


@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized", "request_id": getattr(g, 'request_id', 'unknown')}), 401


@app.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Forbidden", "request_id": getattr(g, 'request_id', 'unknown')}), 403


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found", "request_id": getattr(g, 'request_id', 'unknown')}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed", "request_id": getattr(g, 'request_id', 'unknown')}), 405


@app.errorhandler(413)
def payload_too_large(error):
    return jsonify({"error": "Payload too large", "request_id": getattr(g, 'request_id', 'unknown')}), 413


@app.errorhandler(429)
def too_many_requests(error):
    return jsonify({"error": "Too many requests", "request_id": getattr(g, 'request_id', 'unknown')}), 429


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"error": "Internal server error", "request_id": getattr(g, 'request_id', 'unknown')}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))

    # Set up SSL context for HTTPS - OWASP A02:2021 Cryptographic Failures
    context = None
    ssl_cert = os.environ.get('SSL_CERT')
    ssl_key = os.environ.get('SSL_KEY')

    if ssl_cert and ssl_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2  # Require TLS 1.2 or higher
        context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384')  # Strong ciphers
        context.load_cert_chain(ssl_cert, ssl_key)
        context.options |= ssl.OP_NO_COMPRESSION  # Disable compression (CRIME attack)
        logger.info("SSL context created for HTTPS with modern security settings")
    else:
        logger.warning("Running without HTTPS is not recommended for production")

    app.run(host='0.0.0.0', port=port, ssl_context=context)