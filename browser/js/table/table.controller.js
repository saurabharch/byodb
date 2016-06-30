app.controller('TableCtrl', function ($scope, allTables, $state, TableFactory, $stateParams, $uibModal, HomeFactory) {

	$scope.allTables = allTables;

	$scope.columnArray = [];

	$scope.dbName = $stateParams.dbName

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

	$scope.deleteTheDb = function(){
				console.log('HERE')
		TableFactory.deleteDb($scope.dbName)
		.then(function(){
			HomeFactory.deleteDB($scope.dbName)
		})
		.then(function() {
			$state.go('Home', {}, {reload : true})
		})
	}

});
