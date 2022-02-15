const Sequelize = require('sequelize');
const jwt = require('jsonwebtoken');
const { STRING } = Sequelize;
const config = {
  logging: false,
};
const SECRET_KEY = process.env.JWT;
const bcrypt = require('bcrypt');

if (process.env.LOGGING) {
  delete config.logging;
}
const conn = new Sequelize(
  process.env.DATABASE_URL || 'postgres://localhost/acme_db',
  config
);

//Model:
const User = conn.define('user', {
  username: STRING,
  password: STRING,
});

User.byToken = async (token) => {
  try {
    const verifyUser = jwt.verify(token, SECRET_KEY);
    // console.log('THIS IS VERIFY USER', verifyUser);
    const user = await User.findByPk(verifyUser.userId);
    if (user) {
      return user;
    }
    const error = Error('bad token');
    error.status = 401;
    throw error;
  } catch (ex) {
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
};

User.authenticate = async ({ username, password }) => {
  //   try {
  const userTest = await User.findOne({
    where: {
      username,
    },
  });
  //   } catch (error) {
  //   console.log('USERNAME IS WRONG', error);
  //   }

  if (bcrypt.compare(password, userTest.password)) {
    const hashPass = userTest.password;
    const user = await User.findOne({
      where: {
        username,
        hashPass,
      },
    });
    const token = jwt.sign({ userId: user.id }, SECRET_KEY);
    if (user) {
      return token;
    }
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  } else {
    console.log('PASSWORD IS WRONG');
  }
};

// User.beforeCreate(async (user, options) => {
//   const hashedPassword = await hashPassword(user.password);
//   user.password = hashedPassword;
// });

// bcrypt.hash(myPlaintextPassword, saltRounds, function (err, hash) {
//   // Store hash in your password DB.
// });

User.beforeCreate(async (user, options) => {
  const saltRounds = 5;
  const hashedPassword = await bcrypt.hash(user.password, saltRounds);
  user.password = hashedPassword;
});

const syncAndSeed = async () => {
  await conn.sync({ force: true });
  const credentials = [
    { username: 'lucy', password: 'lucy_pw' },
    { username: 'moe', password: 'moe_pw' },
    { username: 'larry', password: 'larry_pw' },
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map((credential) => User.create(credential))
  );
  return {
    users: {
      lucy,
      moe,
      larry,
    },
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User,
  },
};
