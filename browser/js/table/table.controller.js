app.controller('TableCtrl', function ($scope, allTables, $state, TableFactory, $stateParams) {

	$scope.allTables = allTables;

	// used to hide the list of all tables when in single table state
	$scope.$state = $state;

	$scope.associationTypes = ['hasOne', 'hasMany'];

	$scope.dbName = $stateParams.dbName;

	$scope.makeAssociations = TableFactory.makeAssociations;

});
