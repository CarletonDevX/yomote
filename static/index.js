$(document).ready(function () {
	function colors () {
		var prev = null;
		$('#main .service').each(function(){
			var classes = ['red', 'green', 'yellow', 'purple', 'darkblue', 'turquoise','emerald','blue','belize'];
			var i;
			while(true){
				i = Math.floor(Math.random() * classes.length);
				if (i != prev) { break };
			}
			prev=i;
			$(this).addClass(classes[i]);
		});
	}
	colors();

	$('#nav-search').keydown(function(){
		$( "#content" ).load( "/search?search="+$('#nav-search').val(), function() {
			console.log("loaded script successfully");
			colors();
		} );
	});

	$('#nav-hot').click(function(){
		$( "#content" ).load( "/hot", function() {
			console.log("loaded script successfully");
			colors();
		} );
		return false;
	});

	$('#nav-recent').click(function(){
		$( "#content" ).load( "/recent", function() {
			console.log("loaded script successfully");
			colors();
		} );
		return false;
	});

	$('#nav-about').click(function(){
		$( "#content" ).load( "/static/about.html", function() {
			console.log("loaded script successfully");
		} );
		return false;
	});

	if ($('#nav-create').attr('href')=='#') {
		$('#nav-create').click(function(){
			$( "#content" ).load( "/create", function() {
				console.log("loaded script successfully");
			} );
			return false;
		});
	}
});
