const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const { SNSClient, PublishCommand } = require('@aws-sdk/client-sns');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// 🟦 PostgreSQL
const pool = new Pool({
  user: "adminuser",
  host: "dpg-d13qlbjuibrs73bpbsm0-a.oregon-postgres.render.com",
  database: "nm_ecommerce_db",
  password: "8JS5UP23ylvp3GD5QCQNPOHaejuYfwV2",
  port: "5432"
});

// OTP Memory Store
let otpStore = {};

function generateOTP() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

// AWS SNS Client (v3)
const snsClient = new SNSClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY
  }
});

//  Send OTP via AWS SNS
app.post('/api/send-otp', async (req, res) => {
  const { mobile } = req.body;
  if (!mobile) {
    return res.status(400).send({ success: false, message: "Mobile number is required" });
  }

  const otp = generateOTP();
  otpStore[mobile] = { otp, expiresAt: Date.now() + 2 * 60 * 1000 };

  const message = `Your OTP for NM-ECommerce is ${otp}`;
  const phoneNumber = `+91${mobile}`;

  try {
    const command = new PublishCommand({
      Message: message,
      PhoneNumber: phoneNumber
    });

    await snsClient.send(command);

    res.send({ success: true, message: "OTP sent successfully" });
  } catch (error) {
    console.error("SNS Error:", error);
    res.status(500).send({ success: false, message: "Failed to send OTP via SNS" });
  }
});

//  Register Route
app.post('/api/register', async (req, res) => {
  const { mobile, otp, password } = req.body;

  if (!mobile || !otp || !password) {
    return res.status(400).send({ success: false, message: "All fields are required" });
  }

  const stored = otpStore[mobile];
  if (!stored || stored.otp !== otp || Date.now() > stored.expiresAt) {
    return res.status(400).send({ success: false, message: "Invalid or expired OTP" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (mobile, passkey) VALUES ($1, $2)', [mobile, hashedPassword]);
    delete otpStore[mobile];

    res.send({ success: true, message: "Registered successfully" });
  } catch (err) {
    res.status(500).send({ success: false, message: "DB Error", error: err.message });
  }
});

//  Login Route
app.post('/api/login', async (req, res) => {
  const { mobile, password } = req.body;

  if (!mobile || !password) {
    return res.status(400).send({ success: false, message: "All fields are required" });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE mobile = $1', [mobile]);

    if (result.rows.length === 0) {
      return res.send({ success: false, message: "User not found" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.passkey);

    if (match) {
      res.send({ success: true, message: "Login successful" });
    } else {
      res.send({ success: false, message: "Incorrect password" });
    }
  } catch (err) {
    res.status(500).send({ success: false, message: "Server Error", error: err.message });
  }
});

// Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
