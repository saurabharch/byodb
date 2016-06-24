app.factory('CreatedbFactory', function ($http) {

	var CreatedbFactory = {};

	function resToData(res) {
        return res.data;
    }

    CreatedbFactory.createDB = function(dbName) {
    	return $http.post('/api/masterdb', dbName)
    	.then(resToData)
    }

   CreatedbFactory.createTable = function(table, createdDB) {
    table.dbName = createdDB.dbName;
    return $http.post('/api/clientdb', table)
    .then(resToData);
   }

	return CreatedbFactory; 
})
