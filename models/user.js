const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: function() { return !this.googleID; } }, // require password if not Google user
    role: {
      type: String,
      enum: ["admin", "manager", "worker", "customer"],
      required: true,
    },
    verified: { type: Boolean, default: false },
    verificationToken: { type: String },
    googleID: { type: String }, // To support Google OAuth users
  },
  { timestamps: true }
);

module.exports = mongoose.model("user", userSchema);
