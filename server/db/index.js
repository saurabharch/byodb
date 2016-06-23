'use strict';
var db = require('./_db');

require('./models/user')(db);
require('./models/database')(db);

var User = db.model('user')
var Database = db.model('database')

User.belongsToMany(Database, {through: 'user_database'});
Database.belongsToMany(User, {through: 'user_database'});

module.exports = db;