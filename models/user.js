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
  },
  { timestamps: true }
);

module.exports = mongoose.model("user", userSchema);
