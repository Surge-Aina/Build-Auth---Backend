const jwt = require("jsonwebtoken");
const User = require("../models/user");

module.exports = async function (req, res, next) {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ message: "Access Denied: No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");

    if (!user) return res.status(404).json({ message: "User not found" });

    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};
