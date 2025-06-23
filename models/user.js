const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    role: {
      type: String,
      enum: ["admin", "manager", "worker", "customer"],
      required: true,
    },
    verified: { type: Boolean, default: false },
    verificationToken: { type: String }, // store token or hash for verification

  },
  { timestamps: true }
);

module.exports = mongoose.model("user", userSchema);
