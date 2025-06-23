const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/user");

const router = express.Router();

const passport = require("passport"); // if we use google auth
require("../config/passport");
// if using different email that isnt google
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

//Register Route (POST /api/auth/register)
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password || !role) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if user already exists
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

    await newUser.save();


    // // below is for verification email
    const verificationToken = jwt.sign(
      { userId: newUser._id },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    newUser.verificationToken = verificationToken;
await newUser.save();

const transporter = nodemailer.createTransport({
      service: "Gmail", // can be any email type
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const verificationLink = `${process.env.BASE_URL}/api/auth/verify/${verificationToken}`;

    

    const mailOptions = {
  from: process.env.EMAIL_USER,
  to: newUser.email,
  subject: "Verify your email",
  html: `<p>Please click the following link to verify your email:</p>
         <a href="${verificationLink}">${verificationLink}</a>`,
};

if (process.env.NODE_ENV !== 'test') {
  await transporter.sendMail(mailOptions);
}

    res.status(201).json({ message: "User registered successfully. Please verify your email." });
  } catch (err) {
    console.error("Register error:", err.message);
    res
      .status(500)
      .json({ message: "Registration failed", error: err.message });
  }
});

// below is for google auth

router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// Google will redirect to this URL after authentication
router.get(
  "/google/callback",
  passport.authenticate("google", {
    successRedirect: "", // your frontend URL if success
    failureRedirect: "", // frontend login route redirect
  })
);


// Email verification endpoint
router.get("/verify-email", async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send("Invalid or missing token");

  try {
    const decoded = jwt.verify(token, process.env.EMAIL_VERIFICATION_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) return res.status(400).send("User not found");

    if (user.verified) return res.status(400).send("User already verified");

    // Update user verified status and remove verificationToken
    user.verified = true;
    user.verificationToken = null;
    await user.save();

    // Redirect or respond with success message
    return res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`);
  } catch (err) {
    return res.status(400).send("Invalid or expired token");
  }
});


module.exports = router;
