app.controller('TableCtrl', function ($scope, allTables, $state) {
	$scope.allTables = allTables;

	// used to hide the list of all tables when in single table state
	$scope.$state = $state;

});
