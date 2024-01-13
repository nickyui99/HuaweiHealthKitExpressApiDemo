/**
 * Import function triggers from their respective submodules:
 *
 * const {onCall} = require("firebase-functions/v2/https");
 * const {onDocumentWritten} = require("firebase-functions/v2/firestore");
 *
 * See a full list of supported triggers at https://firebase.google.com/docs/functions
 */

const {onRequest} = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const {setGlobalOptions} = require("firebase-functions/v2");
const axios = require("axios");
const {
	HUAWEI_OAUTH_TOKEN_URL,
	CLIENT_ID,
	CLIENT_SECRET,
	HUAWEI_APP_REDIRECT_URL,
	AUTH_TOKEN,
	REFRESH_TOKEN
} = require("./Constants");
const querystring = require("querystring");
const express = require('express');
const cookieParser = require("cookie-parser");
const {getFirestore} = require("firebase-admin/firestore");
const {initializeApp} = require("firebase-admin/app");
const {response} = require("express");

//Firebase configurations
setGlobalOptions({
	maxInstances: 10
});

//initialize firebase admin
initializeApp();

//initialize firestore
const firestore = getFirestore();
firestore.collection('userRefreshTokens');

const app = express();

//Redirect url
app.get('/redirect', async (request, response) => {
	try {
		const authCode = request.query.code;
		const userId = request.query.user_id;

		logger.log(`AuthCode ${authCode ? authCode : 'not provided'}`);
		logger.log(`User id ${userId ? userId.toString() : 'not provided'}`);

		if (!authCode) {
			throw new Error("Invalid authorization code, please reauthorize the Huawei Health again");
		}

		if (!userId) {
			logger.error("No user query parameter found");
			throw new Error("InvalidQueryParamError");
		}

		//fetch access token
		const tokenResponse = await axios.post(
			HUAWEI_OAUTH_TOKEN_URL,
			querystring.stringify({
				grant_type: AUTH_TOKEN,
				code: authCode,
				client_id: CLIENT_ID,
				client_secret: CLIENT_SECRET,
				redirect_uri: HUAWEI_APP_REDIRECT_URL + `?user_id=${userId}`
			}),
			{
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				}
			}
		);

		firestore.collection('userRefreshTokens').doc(userId).set({
			userId: userId,
			accessToken: tokenResponse.data.access_token,
			refreshToken: tokenResponse.data.refresh_token,
		});

		logger.log("Access token response", tokenResponse);

		response.cookie('access_token', tokenResponse.data.access_token, {maxAge: 3600, httpOnly: true});
		response.send("Huawei Health Authorized. Redirecting...");
	} catch (error) {
		logger.error("Error during access token request", error);

		let statusCode = 401;
		let errorMessage = "Unauthorized";

		if (error.message === "InvalidQueryParamError") {
			statusCode = 400;
			errorMessage = "Invalid query param";
		}

		response.status(statusCode).send({error_message: errorMessage});
	}
});

app.post('/refresh_huawei_health_token', async (request, response) => {
	try {
		const userId = request.body.user_id;
		const accessToken = request.headers.authorization;

		logger.log(`Access Token : ${accessToken ? accessToken : 'not provided'}`);
		logger.log(`User id : ${userId ? userId.toString() : 'not provided'}`);

		if (!userId) {
			logger.error("user_id is not found in request body");
			throw new Error("InvalidParamError");
		}

		if (!accessToken) {
			logger.error("Unauthorized user");
			throw new Error("UnauthorizedError");
		}

		const snapshot = await firestore.collection('userRefreshTokens').doc(userId).get()

		if (snapshot.exists) {
			logger.debug("refresh token:" + snapshot.data().refreshToken)

			const refreshTokenResponse = await axios.post(
				HUAWEI_OAUTH_TOKEN_URL,
				querystring.stringify({
					grant_type: REFRESH_TOKEN,
					refresh_token: snapshot.data().refreshToken.toString(),
					client_id: CLIENT_ID,
					client_secret: CLIENT_SECRET,
					redirect_uri: HUAWEI_APP_REDIRECT_URL + `?user_id=${userId}`
				}),
				{
					headers: {
						"Content-Type": "application/x-www-form-urlencoded"
					}
				}
			)

			response.status(200).send(refreshTokenResponse.data);

		} else {
			throw new Error("Unauthorized")
		}
	} catch (error) {
		logger.error("Error during refresh token request", error);

		let statusCode = 401;
		let errorMessage = "Unauthorized";

		if (error.message === "InvalidParamError") {
			statusCode = 400;
			errorMessage = "Invalid user_id in request body";
		}

		response.status(statusCode).send({error_message: errorMessage});
	}
});


exports.health_demo = onRequest(app);


