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

	$scope.$state = $state; 	// used to hide the list of all tables when in single table state

	$scope.associationTypes = ['hasOne', 'hasMany'];

	$scope.dbName = $stateParams.dbName;

	$scope.makeAssociations = TableFactory.makeAssociations;

	$scope.wherebetween = function(condition) {
		if(condition === "WHERE BETWEEN" || condition === "WHERE NOT BETWEEN") return true;
	}

	$scope.createTable = function(table){
		TableFactory.createTable(table)
		.then(function(){
			$state.go('Table', {dbName:$scope.dbName},{reload:true});
		})
	}

	$scope.type = function() {
		console.log("HELLO JENNA IS THE BEST");
		$scope.allColumns.forEach(function(obj) {
			if(obj.table_name === $scope.query.table1 && obj.column_name === $scope.query.column) $scope.type = obj.data_type;
		})
	}

	// $scope.between

});
