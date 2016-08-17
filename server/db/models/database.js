'use strict';
var Sequelize = require('sequelize');
var pg = require('pg');


module.exports = function (db) {

    db.define('database', {
        name: {
            type: Sequelize.STRING,
            allowNull: false,
            validate: {
            	len: 3
            }
        },
        dbName: {
            type: Sequelize.STRING,
            defaultValue: function(){
                var random = Math.floor(100000000 + Math.random() * 900000000);
                var randomString = random.toString();
                return 'b' + randomString;
            }
        },
        
    }, {
        classMethods: {
            makeClientDatabase: function(createdDB) {
                var dbName = createdDB.dbName;
                var connectionString = 'postgres://localhost:5432/byodb';
                var client = new pg.Client(connectionString);
                client.connect();
                var query = client.query('CREATE DATABASE ' + dbName);
                query.on('end', function() { client.end(); });
                return createdDB; 
            }
        }
    });
};
