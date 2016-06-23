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
        },
        URI: {
        	type: Sequelize.STRING
        }
    });
};