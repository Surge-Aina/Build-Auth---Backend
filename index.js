require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const authRoutes = require("./routes/auth");
//const dashboardRoutes = require("./routes/dashboard");
const taskRoutes = require("./routes/task");
//const userRoutes = require("./routes/users");
const reportRoutes = require("./routes/report");

const app = express();
// app.use(session({ secret: "somevalue"}));
// for google auth
const passport = require("passport");
require("./config/passport");
app.use(passport.initialize());

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use("/api/auth", authRoutes);
// app.use("/api/dashboard", dashboardRoutes);
app.use("/api/tasks", taskRoutes);
//app.use("/api/users", userRoutes);
app.use("/api/report", reportRoutes);
// Test endpoint
//app.get("/", (req, res) => res.send("Hello there!"));
app.get("/api/test", (req, res) => {
  res.send("Hello there!");
});
// Connect to MongoDB and start the server
if (process.env.NODE_ENV !== "test") {
  mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
      console.log("✅ MongoDB connected successfully!");
      app.listen(process.env.PORT, () => {
        console.log(`🚀 Server running on port ${process.env.PORT}`);
      });
    })
    .catch((err) => {
      console.error("❌ MongoDB connection error:", err.message);
    });
}

module.exports = app;
