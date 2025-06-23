const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const mongoose = require("mongoose");
const User = require("../models/user");
require("dotenv").config();

// Configure Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
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
            password: null,       // No password needed for Google users
            role: "customer",     // Default role (customize if needed)
            verified: true,       // Trust Google to verify email
          });
          await user.save();
        } else if (!user.verified) {
          user.verified = true;
          await user.save();
        }

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

// Session management
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

module.exports = passport;
