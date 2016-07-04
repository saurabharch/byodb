app.controller('TableCtrl', function ($scope, allTables, $state, TableFactory, $stateParams, $uibModal, HomeFactory, associations, allColumns) {

	$scope.allTables = allTables;

	$scope.columnArray = [];

	$scope.dbName = $stateParams.dbName

	$scope.associations = associations;

	$scope.allColumns = allColumns;

	$scope.associationTable = $stateParams.dbName + '_assoc';

	$scope.numTables = $scope.allTables.rows.length;

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

	$scope.columnDataType = function() {
		$scope.allColumns.forEach(function(obj) {
			if(obj.table_name === $scope.query.table1 && obj.column_name === $scope.query.column) $scope.type = obj.data_type;
		})
	}

	$scope.selectedAssoc = {};

	// $scope.getAssociated = function(tableName) {
	// 	$scope.associations.forEach(function(row){
	// 		if(!$scope.selectedAssoc[tableName]){ 
	// 			$scope.selectedAssoc[tableName] = [];
	// 		}
	// 		if(row.Table1 === tableName && $scope.selectedAssoc[tableName].indexOf(row.Table2) == -1){
	// 			$scope.selectedAssoc[tableName].push(row.Table2);
	// 		}
	// 		else if(row.Table2 === tableName && $scope.selectedAssoc[tableName].indexOf(row.Table1) == -1){
	// 			$scope.selectedAssoc[tableName].push(row.Table1);	
	// 		} 
	// 	})
	// }

	// $scope.currentTableAssociations = [];

	// associations.forEach(function(row){
	// 	if(row.Table1 === tableName && $scope.selectedAssoc[tableName].indexOf(row.Table2) == -1){
	// 		$scope.currentTableAssociations.push(row.Table2);
	// 	}
	// 	else if(row.Table2 === tableName && $scope.selectedAssoc[tableName].indexOf(row.Table1) == -1){
	// 		$scope.selectedAssoc[tableName].push(row.Table1);	
	// 	} 
	// })

	$scope.submitQuery = TableFactory.submitQuery;

});
