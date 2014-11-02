function myCancelBubble(){
    var evt=window.event;
    if('event' in window) evt=evt||event;
    if(typeof evt !== 'undefined'){
        if(evt.stopPropagation) evt.stopPropagation();
        evt.cancelBubble=true;
    };
    return false;
};

$(document).ready(function () {
  $('.multi-input input').keypress(function (e) {
    if (e.which == 13) {
      var val = $(this).val().trim();
      $(this).val('');
      var ret;
      if (val !== '') {
        e.preventDefault();
        ret = myCancelBubble();
        var name = $(this).parent().attr('data-name');
        $(this).parent().find('ul').append($(
          '<input type="checkbox" style="display:none" '+
          'name="' + name + '" value="' + val + '" checked="checked">' +
          // 'name="' + name + '[' + val + ']" checked="checked">' +
          '<li>' + val + '</li>'
        ));
        return ret;
      } else {
        return true;
      }
    }
  });
});