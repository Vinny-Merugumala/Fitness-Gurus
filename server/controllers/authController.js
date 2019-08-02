const bcrypt = require("bcryptjs");

module.exports = {
  register: async (req, res) => {
    const { firstName, lastName, username, password } = req.body;
    const db = req.app.get("db");
    const result = await db.checkForUser(username);
    if (+result[0].count > 0) {
      res.status(406).json({
        error: "Username Already Taken, Please Choose Another"
      });
    } else {
      const hash = await bcrypt.hash(password, 10);
      await db.registerUser(firstName, lastName, username, hash);

      req.session.user = {
        name: firstName + " " + lastName,
        username
      };
      res.status(200).json(req.session.user);
    }
  },

  login: async (req, res) => {
    const { username, password } = req.body;
    const db = req.app.get("db");
    const info = await db.getUserInfo(username);
    const correct = await bcrypt.compare(password, info[0].password);
    if (correct === true) {
      req.session.user = {
        username,
        name: info[0].first_name + " " + info[0].last_name
      };
      res.status(200).json(req.session.user);
    } else {
      res.status(401).json({
        error: "INCORRECT CREDENTIALS"
      });
    }
  }
};
