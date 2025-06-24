module.exports = function (allowedRoles = []) {
  return function (req, res, next) {
    if (!req.user) {
      return res.status(401).json({ message: "Unauthorized: No user info" });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied: insufficient role" });
    }

    next();
  };
};
