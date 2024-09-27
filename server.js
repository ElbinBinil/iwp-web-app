const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const path = require("path");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const cors = require("cors");
require("dotenv").config();

const app = express();

// CORS middleware
app.use(cors());

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, "public")));

// Middleware to parse JSON and form-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err.message);
    process.exit(1); // Exit if DB connection fails
  });

// Session store in MongoDB
const store = new MongoDBStore({
  uri: process.env.MONGODB_URI,
  collection: "sessions",
});

store.on("error", (error) => {
  console.error("Session store error:", error);
});

// Express session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your_secret_key", // Use a strong secret key from .env
    resave: false,
    saveUninitialized: false,
    store: store,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day expiration
    },
  })
);

// Define user model
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    fullname: String,
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  })
);

// Route to handle signup
app.post("/signup", async (req, res) => {
  try {
    const { fullname, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    // Hash password and create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ fullname, email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Server error during signup" });
  }
});

// Route to handle login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists and compare passwords
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    req.session.email = user.email;

    res.status(200).json({ message: "Login successful" });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error during login" });
  }
});

// Route to fetch dashboard data
app.get("/api/dashboard", async (req, res) => {
  try {
    // Check if the user is logged in (i.e., has a session)
    if (!req.session.email) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // Fetch the user's data based on the session email
    const user = await User.findOne({ email: req.session.email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Send the user data to the client
    res.json({
      fullname: user.fullname,
      courses: user.courses || [],
      outstandingFees: user.outstandingFees || 0,
      grades: user.grades || [],
    });
  } catch (error) {
    console.error("Error fetching dashboard data:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Route to handle logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ message: "Logout failed" });
    }
    res.json({ message: "Logged out successfully" });
  });
});

// Start the server
const port = process.env.PORT || 3000; // Use the environment variable for the port
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
