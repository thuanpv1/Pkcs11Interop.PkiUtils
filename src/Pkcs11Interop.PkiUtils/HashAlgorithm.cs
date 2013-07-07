/*
 *  Pkcs11Interop.PkiUtils - PKI extensions for Pkcs11Interop library
 *  Copyright (c) 2013 JWC s.r.o.
 *  Author: Jaroslav Imrich
 *  
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License version 3
 *  as published by the Free Software Foundation.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *  
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
 *  You can be released from the requirements of the license by purchasing
 *  a commercial license. Buying such a license is mandatory as soon as you
 *  develop commercial activities involving the Pkcs11Interop.PkiUtils software 
 *  without disclosing the source code of your own applications.
 *  
 *  For more information, please contact JWC s.r.o. at info@pkcs11interop.net
 */

using System;

namespace Net.Pkcs11Interop.PkiUtils
{
	/// <summary>
	/// Hash algorithm
	/// </summary>
	public enum HashAlgorithm
	{
		/// <summary>
		/// The SHA1 hash algorithm
		/// </summary>
		SHA1,

		/// <summary>
		/// The SHA256 hash algorithm
		/// </summary>
		SHA256,

		/// <summary>
		/// The SHA384 hash algorithm
		/// </summary>
		SHA384,

		/// <summary>
		/// The SHA512 hash algorithm
		/// </summary>
		SHA512
    }
}
