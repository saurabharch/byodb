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
        }
    }, {
        getterMethods: {
            dbName: function() {
                return 'byodb' + this.id;
            },
            URI: function() {
                return 'postgres://localhost:5432/' + this.dbName;
            }
        },
        classMethods: {
            makeClientDatabase: function(createdDB) {
                var dbName = createdDB.dbName;
                var connectionString = 'postgres://localhost:5432/masterDB';
                var client = new pg.Client(connectionString);
                client.connect();
                var query = client.query('CREATE DATABASE ' + dbName);
                query.on('end', function() { client.end(); });
                return createdDB; 
            }
        }
    });
};
