/*

This seed file is only a placeholder. It should be expanded and altered
to fit the development of your application.

It uses the same file the server uses to establish
the database connection:
--- server/db/index.js

The name of the database used is set in your environment files:
--- server/env/*

This seed file has a safety check to see if you already have users
in the database. If you are developing multiple applications with the
fsg scaffolding, keep in mind that fsg always uses the same database
name in the environment files.

*/

var chalk = require('chalk');
var db = require('./server/db');
var User = db.model('user');
var Database = db.model('database');
var Promise = require('sequelize').Promise;

var seedUsers = function () {

    var users = [
        {
            email: 'testing@fsa.com',
            password: 'password'
        },
        {
            email: 'obama@gmail.com',
            password: 'potus'
        }
    ];

    var creatingUsers = users.map(function (userObj) {
        return User.create(userObj);
    });

    return Promise.all(creatingUsers);

};

// var seedDatabases = function () {

//     var databases = [
//         {
//             name: 'cool colors'
//         },
//         {
//             name: 'things to do for mom'
//         },
//         {
//             name: 'oho'
//         }
//     ];

//     var creatingDatabases = databases.map(function (databaseObj) {
//         return Database.create(databaseObj);
//     });

//     return Promise.all(creatingDatabases);

// };

db.sync({ force: true })
    .then(function () {
       return seedUsers()
    })
    // .then(function () {
    //     var findingdb = Database.findById(1);
    //     var findingdb1 = Database.findById(2);
    //     var findingdb2 = Database.findById(3);
    //     var findinguser = User.findById(1);
    //     var findinguser1 = User.findById(2);;
    //     return Promise.all([findingdb, findingdb1, findingdb2,findinguser,findinguser1]);
    // })
    // .spread(function(user, user1){
    //     console.log(user);
    //     return Promise.all(user.setDatabases([db,db1]), user1.setDatabases([db1,db2]));
    // })
    .then(function () {
        console.log(chalk.green('Seed successful!'));
        process.kill(0);
    })
    .catch(function (err) {
        console.error(err);
        process.kill(1);
    });
