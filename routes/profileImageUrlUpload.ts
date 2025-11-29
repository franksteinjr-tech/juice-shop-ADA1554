/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// List of allowed hostnames for image uploads
const ALLOWED_HOSTNAMES = [
  'images.example.com', // replace with your actual, allowed image host domains
  'cdn.jsdelivr.net',
  'raw.githubusercontent.com',
  'imgur.com',
  'i.imgur.com',
  'upload.wikimedia.org'
  // add more as appropriate
]

// Checks if the URL is safe and allowed
function isValidImageUrl(urlStr: string): boolean {
  try {
    const urlObj = new URL(urlStr);
    // Only allow http/https protocols
    if (urlObj.protocol !== "https:" && urlObj.protocol !== "http:") return false;
    // Hostname must be allowlisted
    if (!ALLOWED_HOSTNAMES.includes(urlObj.hostname)) return false;
    // Prevent localhost, loopback, or private IPs
    const forbiddenHosts = ['localhost', '127.0.0.1'];
    if (forbiddenHosts.includes(urlObj.hostname)) return false;
    // Simple regex to block private IPs
    if (/^10\./.test(urlObj.hostname) ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(urlObj.hostname) ||
        /^192\.168\./.test(urlObj.hostname)) return false;
    return true;
  } catch (e) {
    return false;
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!isValidImageUrl(url)) {
            throw new Error('Invalid image URL: Not allowed or unsafe')
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
