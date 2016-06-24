app.factory('QueryFactory', function ($http) {

	var QueryFactory = {};

	function resToData(res) {
        return res.data;
    }
	return QueryFactory; 
})