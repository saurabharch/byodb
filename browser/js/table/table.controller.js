app.controller('TableCtrl', function ($scope, allTables, $state, TableFactory, $stateParams, $uibModal, HomeFactory, associations, allColumns) {

	$scope.allTables = allTables;

	$scope.columnArray = [];

	$scope.dbName = $stateParams.dbName

	$scope.associations = associations;

	$scope.allColumns = allColumns;

	$scope.associationTable = $stateParams.dbName + '_assoc';

	$scope.add = function() {
		$scope.columnArray.push('1');
	}

	// used to hide the list of all tables when in single table state
	$scope.$state = $state;

	$scope.associationTypes = ['hasOne', 'hasMany'];

	$scope.dbName = $stateParams.dbName;

	$scope.makeAssociations = TableFactory.makeAssociations;

	$scope.createTable = function(table){
		TableFactory.createTable(table)
		.then(function(){
			$state.go('Table', {dbName:$scope.dbName},{reload:true});
		})
	}
});
