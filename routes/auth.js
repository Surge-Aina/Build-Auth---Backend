const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/user");
const router = express.Router();

const passport = require("passport"); // Google OAuth
require("../config/passport");

const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

// Register Route (POST /api/auth/register)
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password || !role) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      role,
      verified: false,
    });

    // Save new user first, before creating token
    await newUser.save();

    // Create email verification token with USER ID, sign with your main JWT secret (simplify)
    const verificationToken = jwt.sign(
      { id: newUser._id }, // Changed key from userId to id for consistency
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // Save token in DB to allow token revocation/validation (optional but recommended)
    newUser.verificationToken = verificationToken;
    await newUser.save();

    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const verificationLink = `${process.env.BASE_URL}/api/auth/verify-email?token=${verificationToken}`; // Fixed URL query param to match verification endpoint below

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: newUser.email,
      subject: "Verify your email",
      html: `<p>Please click the following link to verify your email:</p>
             <a href="${verificationLink}">${verificationLink}</a>`,
    };

    if (process.env.NODE_ENV !== "test") {
      await transporter.sendMail(mailOptions);
    }

    res
      .status(201)
      .json({ message: "User registered successfully. Please verify your email." });
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(500).json({ message: "Registration failed", error: err.message });
  }
});

// Google OAuth routes
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { session: false }), // disable sessions explicitly
  (req, res) => {
    // Google auth successful

    // Generate JWT for the user here to send to frontend instead of relying on sessions
    const token = jwt.sign(
      { id: req.user._id, role: req.user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // You can send token as JSON or redirect with token as query param or cookie
    // Example: redirect with token
    res.redirect(`${process.env.FRONTEND_URL}/oauth-success?token=${token}`);
  }
);

// Email verification endpoint (GET /api/auth/verify-email?token=xxx)
router.get("/verify-email", async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send("Invalid or missing token");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // use same JWT_SECRET here

    const user = await User.findById(decoded.id);
    if (!user) return res.status(400).send("User not found");

    if (user.verified)
      return res.status(400).send("User already verified");

    // Verify user and clear token
    user.verified = true;
    user.verificationToken = null;
    await user.save();

    return res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`);
  } catch (err) {
    console.error("Email verification error:", err);
    return res.status(400).send("Invalid or expired token");
  }
});

module.exports = router;
