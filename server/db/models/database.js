'use strict';
var Sequelize = require('sequelize')

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
        }
    });
};
