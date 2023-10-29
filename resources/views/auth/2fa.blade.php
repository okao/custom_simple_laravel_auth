@extends('auth.layout')

@section('content')
    <div class="flex flex-col items-center justify-center min-h-screen bg-cover bg-center bg-gray-100">
        <div class="w-full max-w-md">
            <div class="bg-white rounded-lg shadow-lg p-8">
            <div class="flex justify-center">
                <img class="h-36 w-36" src="https://d1csarkz8obe9u.cloudfront.net/posterpreviews/company-logo-design-template-e089327a5c476ce5c70c74f7359c5898_screen.jpg?ts=1672291305" alt="Logo">
            </div>

            {{-- error and succsss session messages --}}
            @if (session('error'))
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative my-4" role="alert">
                    <strong class="font-bold">Error!</strong>
                    <span class="block sm:inline">{{ session('error') }}</span>
                </div>
            @endif

            @if (session('success'))
                <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative my-4" role="alert">
                    <strong class="font-bold">Success!</strong>
                    <span class="block sm:inline">{{ session('success') }}</span>
                </div>
            @endif

            <form class="mt-8" method="POST" action="{{ route('submit_2fa') }}">
                @csrf
                <div>
                    <div class="flex justify-center">
                        <h1 class="text-gray-700 font-bold text-2xl">Two Factor Authentication</h1>
                    </div>
                    <label class="block text-gray-700 font-bold mb-2" for="code">
                        Code
                    </label>
                    <input name="code" type="number" class="appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="code" type="text" placeholder="Code">
                    </div>
                    <div class="mt-8">
                        <div class="text-sm text-gray-700">
                            {{ __('Please confirm access to your account by entering the authentication code provided by your authenticator application.') }}
                        </div>
                        <div class="flex items-center justify-between mt-4">
                            <div class="text-sm text-gray-700 w-full">
                                <span id="timer"></span>

                                <script>

                                    // keep the funtion in loop
                                    document.getElementById("timer").innerHTML = '';
                                    loop_event();
                                    //now i want the function initiallially to show OTP button and then after 30 seconds to show the timer
                                    function loop_event() {
                                        //show the OTP button
                                        document.getElementById("timer").innerHTML = '<button type="button" class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="button" onclick="resend_otp()">Request OTP</button>';
                                    }

                                    // function to Send otp
                                    function resend_otp() {

                                        //call the function to start the countdown
                                        startTimer();

                                        //call the function to make ajax request
                                        call_request();

                                        //hide the button
                                        document.getElementById("timer").innerHTML = '';

                                        //show the timer until 30 seconds
                                        document.getElementById("timer").innerHTML =
                                        '<button type="submit" class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4' +
                                        'rounded focus:outline-none focus:shadow-outline" type="button">Proceed with 2FA</button><br><br>' +
                                        '<div class="w-full bg-gray-100 py-5 text-center" id="countdown">30 seconds remaining</div>';
                                    }

                                    //function to start the countdown
                                    function startTimer() {
                                        var timeleft = 30;
                                        var downloadTimer = setInterval(function() {
                                            timeleft--;
                                            document.getElementById("countdown").textContent = timeleft + " seconds remaining";
                                            if (timeleft <= 1)
                                                clearInterval(downloadTimer);
                                        }, 1000);
                                    }


                                    function call_request(params) {
                                        //turn above into ajax
                                        $.ajax({
                                            url: "{{ route('verification.resend') }}",
                                            type: "POST",
                                            // pass the cookies along
                                            xhrFields: {
                                                withCredentials: true
                                            },
                                            data: {
                                                _token: '{{ csrf_token() }}'
                                            },
                                            beforeSend: function() {
                                                document.getElementById("timer").innerHTML = '';
                                            },
                                            success: function(response) {
                                                //call the function again after 2 seconds
                                                setTimeout(function() {
                                                    loop_event();
                                                }, 30000);
                                            },
                                            error: function(xhr) {

                                                //if 401 then reload the page to redirect to login
                                                if (xhr.status == 401) {
                                                    location.reload();
                                                }

                                                //show the button to Send otp with OnClick event
                                                setTimeout(function() {
                                                    document.getElementById("timer").innerHTML = '<button type="button" class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="button" onclick="resend_otp()">Request OTP</button>';
                                                }, 30000);
                                            }
                                        });
                                    }
                                </script>


                            </div>
                        </div>





                    {{-- <button type="submit" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="button">
                        Proceed with 2FA
                    </button> --}}
                </div>
            </form>

            </div>
        </div>
    </div>
@endsection
