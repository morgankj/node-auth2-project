const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const User = require("../users/users-model");
const makeToken = require("./auth-token-builder");

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;
  console.log("ROLENAME: ", req.body.role_name, "-");

  const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS);
  user.password = hash;

  User.add(user)
    .then((createdUser) => {
      res.status(201).json(createdUser);
    })
    .catch(next);
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  let { username, password } = req.body;

  User.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = makeToken(user);
        res.status(200).json({ message: `${username} is back!`, token });
      } else {
        next({ status: 401, message: "Invalid credentials" });
      }
    })
    .catch(next);
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
