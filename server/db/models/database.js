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
        dbName: {
            type: Sequelize.STRING,
            defaultValue: function(){
                var random = Math.floor(100000000 + Math.random() * 900000000);
                var randomString = random.toString();
                return 'b' + randomString;
            }
        }
    }, {
        // getterMethods: {
        //     URI: function() {
        //         return 'postgres://localhost:5432/' + this.dbName;
        //     }
        // }
    });
};
