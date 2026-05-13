# 🚀 Quick Star t Guide - AI-SOC Phase 1

## Option 1: Quick Start with SQLite (Easiest)

### 1. Setup Environment
```bash
# Navigate to project
cd AI-SOC

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure
```bash
# Copy environment template
cp .env.example .env

# .env will use SQLite by default - no changes needed!
```

### 3. Run the Application
```bash
# Start the server
python main.py
```

The API is now running at: **http://localhost:8000**

### 4. Test with Sample Data
```bash
# In a new terminal (keep the server running)
# Activate virtual environment again
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Generate test data
python generate_test_data.py
```

This will:
- Create 150 normal security events
- Train the ML model
- Create 15 anomalous events
- Show alerts generated

### 5. Explore the API
Open in your browser:
- **API Documentation**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/health

---

## Option 2: Docker (Production-like)

### 1. Start with Docker Compose
```bash
# Start all services (API + PostgreSQL + Redis)
docker-compose up -d

# Check logs
docker-compose logs -f app

# Wait for services to be healthy
docker-compose ps
```

### 2. Generate Test Data
```bash
# Run the test data generator
python generate_test_data.py
```

### 3. Stop Services
```bash
docker-compose down
```

---

## Option 3: Manual PostgreSQL Setup

### 1. Install PostgreSQL
```bash
# On Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib

# On macOS
brew install postgresql
```

### 2. Create Database
```bash
# Switch to postgres user
sudo -u postgres psql

# In PostgreSQL prompt:
CREATE DATABASE aisoc_db;
CREATE USER aisoc WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE aisoc_db TO aisoc;
\q
```

### 3. Configure Environment
```bash
# Edit .env file
nano .env

# Update this line:
DATABASE_URL=postgresql://aisoc:your_secure_password@localhost:5432/aisoc_db
```

### 4. Run Application
```bash
python main.py
```

---

## 📝 Basic Usage Examples

### Create a Security Event
```bash
curl -X POST "http://localhost:8000/api/v1/events" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "network",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.50",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "bytes_sent": 1024,
    "bytes_received": 2048,
    "duration": 1.5,
    "packet_count": 15
  }'
```

### Get All Events
```bash
curl "http://localhost:8000/api/v1/events?limit=10"
```

### Get Anomalies Only
```bash
curl "http://localhost:8000/api/v1/events?anomalies_only=true"
```

### Get Alerts
```bash
curl "http://localhost:8000/api/v1/alerts"
```

### Train Model
```bash
curl -X POST "http://localhost:8000/api/v1/models/train" \
  -H "Content-Type: application/json" \
  -d '{
    "contamination_rate": 0.05,
    "n_estimators": 100
  }'
```

### Predict if Event is Anomalous
```bash
curl -X POST "http://localhost:8000/api/v1/models/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "network",
    "src_ip": "192.168.1.100",
    "bytes_sent": 1000000,
    "bytes_received": 5000000,
    "duration": 300,
    "packet_count": 5000
  }'
```

### Get Statistics
```bash
curl "http://localhost:8000/api/v1/events/statistics/summary?hours=24"
```

---

## 🧪 Testing Workflow

### Complete Test Cycle

1. **Start the server**
   ```bash
   python main.py
   ```

2. **Generate test data**
   ```bash
   python generate_test_data.py
   ```

3. **View in browser**
   - Go to http://localhost:8000/docs
   - Try out different endpoints
   - Check GET /api/v1/alerts for detected anomalies

4. **Update an alert**
   - In Swagger UI, go to PATCH /api/v1/alerts/{alert_id}
   - Set status to "investigating"
   - Add notes about your investigation

---

## 🐛 Troubleshooting

### "Model not trained" error
**Solution:** You need at least 100 events before training
```bash
python generate_test_data.py
```

### Port 8000 already in use
**Solution:** Kill the existing process or change port in .env
```bash
# Linux/Mac
lsof -ti:8000 | xargs kill -9

# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

### Database connection errors
**Solution:** Check your DATABASE_URL in .env

### Module not found errors
**Solution:** Make sure virtual environment is activated
```bash
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

---

## 📊 Expected Results

After running `generate_test_data.py`, you should see:

✅ **150 normal events** created  
✅ **ML model trained** with ~150 samples  
✅ **15 anomalous events** created  
✅ **10-15 alerts** generated (high/critical severity)  
✅ **Anomaly rate**: ~9-10%  

---

## 🎯 Next Steps

1. **Explore the API** - Try creating different types of events
2. **Understand the ML** - Check which events are flagged as anomalies
3. **Tune the model** - Adjust contamination_rate and retrain
4. **Add more event types** - Expand beyond network events
5. **Move to Phase 2** - Start building compliance mapping!

---

## 📚 Resources

- API Documentation: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- Health Check: http://localhost:8000/health
- Full README: See README.md

---

**Questions?** Check the main README.md or create an issue!

**Happy Testing! 🚀**
