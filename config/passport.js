const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const LocalStrategy = require("passport-local").Strategy; // ✅ Added LocalStrategy for email/password login
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const User = require("../models/user");
require("dotenv").config();

// ✅ Local Strategy: for logging in with email + password
passport.use(
  new LocalStrategy(
    {
      usernameField: "email", // Match your frontend field
      passwordField: "password",
    },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });

        if (!user) {
          return done(null, false, { message: "Incorrect email." });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return done(null, false, { message: "Incorrect password." });
        }

        // ✅ Optional: Block unverified users
        if (!user.verified) {
          return done(null, false, { message: "Please verify your email." });
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// ✅ Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true, // Needed to access `req.session` if desired
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        const username = profile.displayName || "GoogleUser";

        if (!email) {
          return done(new Error("No email found in Google profile"), null);
        }

        let user = await User.findOne({ email });

        if (!user) {
          user = new User({
            username,
            email,
            password: null,       // 🔒 Password not stored for Google users
            role: "customer",     // ✅ Default role (or get from req/session if needed)
            verified: true,       // ✅ Trust Google
            googleID: profile.id, // ✅ Optional: track Google ID
          });
          await user.save();
        } else if (!user.verified) {
          user.verified = true;
          await user.save();
        }

        return done(null, user);
      } catch (err) {
        console.error("Google Strategy Error:", err);
        return done(err, null);
      }
    }
  )
)

module.exports = passport;
