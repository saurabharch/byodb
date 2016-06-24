app.controller('CreatedbCtrl', function ($scope, CreatedbFactory) {

	$scope.createdDB = false;

	// $scope.columnIndex = 0;

	// $scope.increment = function() {
	// 	$scope.columnIndex ++;
	// 	$scope.$digest();
	// }

	$scope.columnArray = [];

	$scope.add = function() {
		$scope.columnArray.push('1');
	}

	$scope.createDB = function(name) {
		CreatedbFactory.createDB(name)
		.then(function(data) {
			$scope.createdDB = data;
			console.log(data);
		})
	}

	$scope.createTable = CreatedbFactory.createTable;

});
