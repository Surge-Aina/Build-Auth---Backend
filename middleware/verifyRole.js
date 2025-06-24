module.exports = function verifyRole(requiredRole) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Unauthorized: No user info" });
    }

    if (req.user.role !== requiredRole) {
      return res.status(403).json({ message: "Access denied: insufficient role" });
    }

    next();
  };
};
