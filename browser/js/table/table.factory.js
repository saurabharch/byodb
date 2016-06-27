app.factory('TableFactory', function ($http) {

	var TableFactory = {};

	function resToData(res) {
        return res.data;
    }

    TableFactory.getAllTables = function(dbName){
    	return $http.get('/api/clientdb/' + dbName)
    	.then(resToData)
    }

    TableFactory.getSingleTable = function(dbName, tableName){
        return $http.get('/api/clientdb/' + dbName + '/' + tableName)
        .then(resToData)
    }

    TableFactory.filter = function(dbName, tableName, data) {
        return $http.put('/api/clientdb/' + dbName + '/' + tableName, data)
    }

	return TableFactory; 
})