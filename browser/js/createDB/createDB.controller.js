app.controller('CreatedbCtrl', function ($scope, $state, CreatedbFactory) {

	$scope.createdDB = false;
        $scope.columnArray = [];

	$scope.add = function() {
		$scope.columnArray.push('1');
	}

	$scope.createDB = function(name) {
		CreatedbFactory.createDB(name)
		.then(function(data) {
			$scope.createdDB = data;
		})
	}

	$scope.createTable = function(){
		CreatedbFactory.createTable;
		$state.go('Table', {dbName: $scope.createdDB.dbName})
	}
});
