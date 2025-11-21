const statusCheckInterval = 1000;

var lastRule = $('#rule').val();
var submitted = false;
var checkingStatus = false;
var lastStatusHash = null;
var lastSubmissionNull = false;

var tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
var tooltips = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))

var toastLiveCheck = document.getElementById('liveToastCheck')
var toastLiveSubmit = document.getElementById('liveToastSubmit')
var toastLiveCheckAnalyzed = document.getElementById('liveToastCheckAnalyzed')
var toastLiveSubmitAnalyzed = document.getElementById('liveToastSubmitAnalyzed')

var nextScenarioAvailable = null;
var toastLiveNextScenario = document.getElementById('liveToastNextScenario')
var toastLiveTestsUpdated = document.getElementById('liveToastTestsUpdated')

function manageButton(e) {
  rule = $('#rule').val();

  if ((rule == lastRule) && (submitted == true)) {
    $('#check').prop('disabled', true);
    $('#submit').prop('disabled', true);
  } else if ((rule == lastRule) && (submitted == false)) {
    $('#check').prop('disabled', true);
    $('#submit').prop('disabled', false);
  } else {
    $('#check').prop('disabled', false);
    $('#submit').prop('disabled', false);
  }
}

function submitScenario(e) {
  buttonElement = e.target;
  rule = $('#rule').val();

  if (buttonElement.id == "check") {
    submitted = false;
  } else if (buttonElement.id == "submit") {
    submitted = true;
  } else {
    submitted = null;
  }

  lastRule = rule;
  manageButton(e);

  csrfmiddlewaretoken = $('#form').find("[name='csrfmiddlewaretoken']").val();

  action = $('#' + buttonElement.id).attr("action");
  var body = {
    rule: rule,
    check_only: !submitted,
    csrfmiddlewaretoken: csrfmiddlewaretoken,
  };

  if (submitted) {
    var toast = bootstrap.Toast.getOrCreateInstance(toastLiveSubmit);
  } else {
    var toast = bootstrap.Toast.getOrCreateInstance(toastLiveCheck);
  }
  toast.show();

  $.post($('#form').prop("action"), body, (data, status) => {
    if (data.formatted == null) {
      $('#formatted-rule').html("<p>Submitted rule contained invalid syntax.</p>");
    } else {
      $('#formatted-rule').html(data.formatted);
    }
    if ($('#formatted-rule-div').hasClass('invisible')) {
      $('#formatted-rule-div').removeClass('invisible');
    }
    if (submitted) {
      $('#submitted-rule').val(rule);
      if (data.formatted == null) {
        $('#formatted-submitted-rule').html("<p>Submitted rule contained invalid syntax.</p>");
      } else {
        $('#formatted-submitted-rule').html(data.formatted);
      }
      if ($('#submitted-rule-div').hasClass('invisible')) {
        $('#submitted-rule-div').removeClass('invisible');
      }
    }

    $('#messages').html("");

    var date = new Date(data.submitted_at);

    if (data.has_errors == true) {
      $('#messages').append('<div class="card border-danger bg-transparent m-1"><div class="card-header text-danger lead">Feedback</div><div class="card-body"><p class="card-text">Submitted signature could not be parsed by Suricata. Check output for more details. (' + date.toLocaleTimeString() + ')</p></div></div>');
    } else {
      $('#messages').append('<div class="card border-success bg-transparent m-1"><div class="card-header text-success lead">Feedback</div><div class="card-body"><p class="card-text">Signature submitted and parsed successfully. (' + date.toLocaleTimeString() + ')</p></div></div>');
    }

    var suricataOutput = "";
    data.output.split("\n").forEach(line => {
      suricataOutput += '<p class="m-0">' + line + '</p>';
    });

    $('#messages').append('<div class="card border-info bg-transparent m-1"><div class="card-header text-info lead">Suricata output</div><div class="card-body overflow-auto text-nowrap"><p class="card-text">' + suricataOutput + '</p></div></div>');
  
    toast.hide();
    if (submitted) {
      bootstrap.Toast.getOrCreateInstance(toastLiveSubmitAnalyzed).show();
    } else {
      bootstrap.Toast.getOrCreateInstance(toastLiveCheckAnalyzed).show();
    }
  });

  checkStatus()
}

function checkStatus() {
  if (checkingStatus == true) {
    return
  }
  checkingStatus = true;

  $.get($('#status').attr('action'))
    .done(function (data, status) {
      statusHash = JSON.stringify(data);
      if ((lastStatusHash != null) & (statusHash == lastStatusHash)) {
        checkingStatus = false;
        return
      }

      $('#status').html("");
      if (data.submission == null) {
        lastSubmissionNull = true;
      } else {
        lastSubmissionNull = false;
      }

      var pendingResults = false;

      data.tests.forEach(test => {
        result = null;
        // Go over the results to see if a corresponding result exists
        if (data.results != null) {
          data.results.forEach(r => {
            if (test.id == r.test) {
              result = r;
            }
          });
        }

        if ((lastSubmissionNull == true) & (result == null)) {
          testResultMsg = "No submission was found, submit something to see test results.";
          $('#status').append('<span class="d-inline-flex p-2"><div class="text-bg-info p-1" data-bs-toggle="tooltip" data-bs-placement="top" title="' + testResultMsg + '"><i class="bi bi-question" role="status"></i><em class="text-white">' + test.title + '</em></div></span>')
        } else if ((lastSubmissionNull == false) & (result == null)) {
          pendingResults = true;
          testResultMsg = "Tests are currently running. Results will appear automatically once completed.";
          $('#status').append('<span class="d-inline-flex p-2"><div class="text-bg-info p-1" data-bs-toggle="tooltip" data-bs-placement="top" title="' + testResultMsg + '"><div class="spinner-border spinner-border-sm" role="status"></div><em class="text-white">' + test.title + '</em></div></span>')
        } else if (result.status == "Failure") {
          if (test.expected) {
            testResultMsg = "This test was failed since the rule raised zero alerts, whereas one is expected.";
          } else {
            testResultMsg = "This test was failed since the rule raised alerts whereas zero alerts are expected.";
          }
          $('#status').append('<span class="d-inline-flex p-2"><div class="text-bg-danger p-1" data-bs-toggle="tooltip" data-bs-placement="top" title="' + testResultMsg + '"><i class="bi bi-x-lg" role="status"></i><a class="link-underline-opacity-0" href="' + window.location + '/test/' + test.id + '"><em class="text-white">' + test.title + '</em></a></div></span>')
        } else if (result.status == "Warning") {
          testResultMsg = "This test was passed with a warning since the rule raised more than one alert, whereas only one alert is expected.";
          $('#status').append('<span class="d-inline-flex p-2"><div class="text-bg-warning p-1" data-bs-toggle="tooltip" data-bs-placement="top" title="' + testResultMsg + '"><i class="bi bi-x" role="status"></i><a class="link-underline-opacity-0" href="' + window.location + '/test/' + test.id + '"><em class="text-white">' + test.title + '</em></a></div></span>')
        } else if (result.status == "Success") {
          if (test.expected) {
            testResultMsg = "This test was passed successfully since the rule raised exactly one alert as expected.";
          } else {
            testResultMsg = "This test was passed successfully since the rule raised zero alerts as expected.";
          }
          $('#status').append('<span class="d-inline-flex p-2"><div class="text-bg-success p-1" data-bs-toggle="tooltip" data-bs-placement="top" title="' + testResultMsg + '"><i class="bi bi-check" role="status"></i><a class="link-underline-opacity-0" href="' + window.location + '/test/' + test.id + '"><em class="text-white">' + test.title + '</em></a></div></span>')
        }
      });

      // Remove stale tooltips
      tooltips.forEach(tooltip => {
        tooltip.hide();
      });
      // Activate newly added tooltips
      tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
      tooltips = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))

      $('#scenario-navigation').html("");
      if (data.previous_scenario) {
        $('#scenario-navigation').append('<div class="col-12 col-sm-6"><div class="row justify-content-center"><a href="/scenario/' + data.previous_scenario.id + '" class="m-2 btn btn-primary text-white d-inline-flex w-auto" role="button"><i class="mx-2 bi bi-arrow-bar-left"></i>Previous scenario</a></div></div>')
      }
      if (data.next_scenario_unlocked == true && data.next_scenario) {
        if (nextScenarioAvailable == false) {
          bootstrap.Toast.getOrCreateInstance(toastLiveCheck).show();
        }
        nextScenarioAvailable = true;
        $('#scenario-navigation').append('<div class="col-12 col-sm-6"><div class="row justify-content-center"><a href="/scenario/' + data.next_scenario.id + '" class="m-2 btn btn-primary text-white d-inline-flex w-auto" role="button">Next scenario<i class="mx-2 bi bi-arrow-bar-right"></i></a></div></div>')
      } else {
        nextScenarioAvailable = false;
      }
    
      if (lastStatusHash != null) {
        bootstrap.Toast.getOrCreateInstance(toastLiveTestsUpdated).show();
      }
      lastStatusHash = statusHash;

      checkingStatus = false;
    })
    .fail(function(jqXHR, textStatus, errorThrown) {
      checkingStatus = false;
    });
}

if ($('#rule').val() == $('#submitted-rule').val()) {
  submitted = true;
}
manageButton();

var intervalId = setInterval(checkStatus, statusCheckInterval);