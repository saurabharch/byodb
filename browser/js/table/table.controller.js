app.controller('TableCtrl', function ($scope, allTables, $state, TableFactory, $stateParams) {

	$scope.allTables = allTables;

	$scope.columnArray = [];

	$scope.add = function() {
		$scope.columnArray.push('1');
	}

	$scope.$state = $state; // used to hide the list of all tables when in single table state

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
