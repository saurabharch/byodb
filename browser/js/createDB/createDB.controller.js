app.controller('CreatedbCtrl', function ($scope, CreatedbFactory) {

	$scope.createdDB = false;

	$scope.createDB = function(name) {
		CreatedbFactory.createDB(name)
		.then(function(data) {
			$scope.createdDB = data;
			console.log(data);
		})
	}

	$scope.createTable = CreatedbFactory.createTable;

});
